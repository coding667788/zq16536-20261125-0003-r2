"""Topological interleaving engine and prefix replay semantics."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any

from .caseio import CaseIndex, topological_order
from .closures import dependency_closure


@dataclass
class EngineState:
    aliases: dict[str, str] = field(default_factory=dict)
    revoked_persons: set[str] = field(default_factory=set)
    revoked_votes: set[str] = field(default_factory=set)
    # vote id -> (resolved person id or "", cast_allowed, static_ok)
    votes: dict[str, tuple[str, bool, bool]] = field(default_factory=dict)

    def clone(self) -> "EngineState":
        return EngineState(
            dict(self.aliases),
            set(self.revoked_persons),
            set(self.revoked_votes),
            dict(self.votes),
        )

    def key(self, mask: int) -> tuple[Any, ...]:
        return (
            mask,
            tuple(sorted(self.aliases.items())),
            tuple(sorted(self.revoked_persons)),
            tuple(sorted(self.revoked_votes)),
            tuple(sorted((k, v[0], v[1], v[2]) for k, v in self.votes.items())),
        )


def _kind(event: dict[str, Any]) -> str:
    return str(event.get("kind", ""))


def vote_static_spec(index: CaseIndex, event_id: str, candidate: dict[str, Any], closure_digest: str) -> dict[str, Any] | None:
    e = index.events[event_id]
    if _kind(e) not in ("vote", "approval_receipt", "approval", "receipt"):
        return None
    bound = e.get("closure_digest", e.get("dependency_closure_digest"))
    phase = str(e.get("phase", ""))
    wanted_phase = str(candidate.get("phase", ""))
    if bound != closure_digest:
        return {"static_ok": False, "reason": "wrong_closure_digest", "event_id": event_id}
    if phase not in ("", "*", wanted_phase):
        return {"static_ok": False, "reason": "wrong_phase", "event_id": event_id}
    gid = e.get("group_id", e.get("group"))
    if not isinstance(gid, str) or not gid:
        return {"static_ok": False, "reason": "missing_group_id", "event_id": event_id}
    indep = e.get("independence_key", e.get("independence_id", gid))
    return {
        "static_ok": True,
        "reason": "eligible_record",
        "event_id": event_id,
        "group_id": gid,
        "group_name": e.get("group_name"),
        "independence_key": str(indep),
        "person_id": e.get("person_id"),
        "auth_ref": e.get("auth_ref", e.get("alias", e.get("ref"))),
    }


def candidate_vote_specs(index: CaseIndex, candidate: dict[str, Any], closure_digest: str) -> dict[str, dict[str, Any]]:
    phase = str(candidate.get("phase", ""))
    ids = list(index.vote_index.get((closure_digest, phase), []))
    ids.extend(index.vote_index.get((closure_digest, ""), []))
    specs: dict[str, dict[str, Any]] = {}
    for vid in dict.fromkeys(ids):
        spec = vote_static_spec(index, vid, candidate, closure_digest)
        if spec is not None:
            specs[vid] = spec
    return specs


def apply_event(
    index: CaseIndex,
    state: EngineState,
    event_id: str,
    specs: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Apply one record in a chosen linear order and return a small trace."""
    e = index.events[event_id]
    kind = _kind(e)
    trace: dict[str, Any] = {"event_id": event_id, "kind": kind}

    if kind in ("alias_binding", "person_alias", "alias"):
        ref = e.get("auth_ref", e.get("alias", e.get("ref")))
        pid = e.get("person_id")
        if isinstance(ref, str) and isinstance(pid, str):
            previous = state.aliases.get(ref)
            state.aliases[ref] = pid
            trace.update(auth_ref=ref, person_id=pid, previous_person_id=previous, label_moved=previous not in (None, pid))

    elif kind in ("revocation", "revoke", "suspension"):
        action = str(e.get("action", "revoke")).lower()
        ttype = str(e.get("target_type", e.get("subject_type", "person")))
        tid = e.get("target_id", e.get("subject_id"))
        if isinstance(tid, str):
            target = state.revoked_votes if ttype == "vote" else state.revoked_persons
            if action in ("restore", "unrevoke", "reinstate", "lift"):
                target.discard(tid)
                trace.update(action="restore", target_type=ttype, target_id=tid)
            else:
                target.add(tid)
                trace.update(action="revoke", target_type=ttype, target_id=tid)

    elif kind in ("vote", "approval_receipt", "approval", "receipt"):
        spec = (specs or {}).get(event_id)
        if spec is None:
            # Still remember that an out-of-scope vote exists only if a spec was
            # deliberately supplied.  Without a spec there is nothing to tally.
            return trace
        ref = spec.get("auth_ref")
        claimed = spec.get("person_id")
        resolved: str | None = None
        reason = "valid"
        identity_ok = True
        if ref:
            resolved = state.aliases.get(str(ref))
            if resolved is None:
                identity_ok = False
                reason = "unbound_auth_ref_at_receipt_position"
            elif claimed is not None and str(claimed) != resolved:
                identity_ok = False
                reason = "auth_ref_bound_to_other_natural_person"
        else:
            resolved = str(claimed) if claimed is not None else None
            if resolved is None:
                identity_ok = False
                reason = "missing_natural_person"

        cast_ok = identity_ok and bool(resolved) and resolved not in state.revoked_persons and event_id not in state.revoked_votes
        if not cast_ok and reason == "valid":
            reason = "suspension_active_at_receipt_position"
        static_ok = bool(spec.get("static_ok"))
        state.votes[event_id] = (resolved or "", cast_ok, static_ok)
        trace["vote_assessment"] = {
            "event_id": event_id,
            "resolved_person_id": resolved,
            "cast_allowed": cast_ok,
            "static_ok": static_ok,
            "reason": reason,
        }

    return trace


def tally_state(
    state: EngineState,
    specs: dict[str, dict[str, Any]],
    threshold: int,
    required_groups: int,
    blocked: set[str] | frozenset[str] | None = None,
) -> dict[str, Any]:
    valid_votes: list[str] = []
    persons: set[str] = set()
    group_ids: set[str] = set()
    independence_keys: set[str] = set()
    invalid: list[dict[str, Any]] = []

    for vid, (resolved, cast_ok, static_ok) in sorted(state.votes.items()):
        if blocked is not None and vid in blocked:
            continue
        spec = specs.get(vid, {})
        if not static_ok:
            invalid.append({"event_id": vid, "reason": spec.get("reason", "statically_invalid")})
            continue
        currently_revoked = resolved in state.revoked_persons or vid in state.revoked_votes
        if not resolved or not cast_ok or currently_revoked:
            reason = "currently_revoked" if currently_revoked else "not_valid_at_receipt_position"
            invalid.append({"event_id": vid, "person_id": resolved or None, "reason": reason})
            continue
        valid_votes.append(vid)
        persons.add(resolved)
        group_ids.add(spec["group_id"])
        independence_keys.add(spec["independence_key"])

    # One natural person is one effective vote, even after alias changes or
    # duplicate receipts.  valid_vote_ids above are active receipts; the
    # distinct person count is the threshold count.
    passed = len(persons) >= threshold
    if required_groups > 0:
        passed = passed and len(group_ids) >= required_groups and len(independence_keys) >= required_groups
    return {
        "passed": passed,
        "effective_vote_count": len(persons),
        "threshold": threshold,
        "distinct_natural_person_ids": sorted(persons),
        "valid_vote_ids": valid_votes,
        "group_ids": sorted(group_ids),
        "independence_keys": sorted(independence_keys),
        "required_independent_groups": required_groups,
        "invalid_or_inactive": invalid,
    }


def replay_order(
    index: CaseIndex,
    ordered_ids: list[str],
    specs: dict[str, dict[str, Any]],
    threshold: int,
    required_groups: int,
    state: EngineState | None = None,
    blocked: set[str] | frozenset[str] | None = None,
) -> tuple[EngineState, list[dict[str, Any]], dict[str, Any]]:
    state = state.clone() if state is not None else EngineState()
    steps: list[dict[str, Any]] = []
    for eid in ordered_ids:
        trace = apply_event(index, state, eid, specs)
        trace["tally"] = tally_state(state, specs, threshold, required_groups, blocked)
        steps.append(trace)
    return state, steps, tally_state(state, specs, threshold, required_groups, blocked)


class BaseCache:
    def __init__(self) -> None:
        self._cache: dict[tuple[str, frozenset[str], int, int], tuple[EngineState, list[str]]] = {}

    def get(
        self,
        index: CaseIndex,
        prefix_ids: set[str],
        specs: dict[str, dict[str, Any]],
        threshold: int,
        required_groups: int,
        cache_key: str = "",
        state_key: Any | None = None,
        order_hint: list[str] | None = None,
        order_builder: Any | None = None,
    ) -> tuple[EngineState, list[str]]:
        key = (
            cache_key,
            state_key if state_key is not None else frozenset(prefix_ids),
            threshold,
            required_groups,
        )
        cached = self._cache.get(key)
        if cached is not None:
            return cached[0].clone(), list(cached[1])
        if order_hint is not None:
            ordered = list(order_hint)
        elif order_builder is not None:
            ordered = list(order_builder())
        else:
            ordered = topological_order(prefix_ids, index.preds)
        state = EngineState()
        for eid in ordered:
            apply_event(index, state, eid, specs)
        value = (state.clone(), ordered)
        self._cache[key] = value
        return state, ordered


def resolve_window_ids(index: CaseIndex, candidate: dict[str, Any]) -> list[str]:
    wid = candidate.get("window_id")
    if wid is not None:
        if wid not in index.windows:
            # Maybe window defined inline by candidate.
            ids = candidate.get("ambiguous_event_ids", [])
        else:
            ids = index.windows[wid].get("event_ids", [])
    else:
        ids = candidate.get("ambiguous_event_ids", [])
    ids = [eid for eid in ids if eid in index.events]
    # Include any post-checkpoint causal ancestor omitted from the declared
    # window; checkpoint ancestors are already in the locked base.
    extra: set[str] = set()
    for eid in list(ids):
        for a in index.ancestor_closure([eid]):
            if a not in index.checkpoint:
                extra.add(a)
    result = list(dict.fromkeys(ids + sorted(extra)))
    return result


def prepare_analysis(
    index: CaseIndex,
    candidate: dict[str, Any],
    blocked: set[str] | frozenset[str] | None = None,
    base_cache: BaseCache | None = None,
) -> dict[str, Any]:
    blocked_set = set(blocked or ())
    closure = dependency_closure(index, candidate, blocked_set)
    if closure["status"] != "resolved":
        return {"closure": closure, "specs": {}, "window_ids": [], "base_state": EngineState(), "base_order": [], "threshold": 0, "required_groups": 2}

    threshold, required_groups = index.phase_policy(candidate.get("phase"))
    closure_digest = closure["closure_digest"]
    specs = candidate_vote_specs(index, candidate, closure_digest)

    cache = base_cache or BaseCache()
    cache_name = str(candidate.get("id")) + ":" + closure_digest
    blocked_prefix = blocked_set & index.checkpoint
    blocked_modifiers = {
        eid
        for eid in blocked_prefix
        if index.events[eid].get("kind") in ("alias_binding", "person_alias", "alias", "revocation", "revoke", "suspension")
    }

    if not blocked_modifiers:
        # Replay the 100k-event locked prefix at most once per candidate.
        # Held receipts are left in the state but excluded by tally(blocked=).
        base_state, base_order = cache.get(
            index,
            index.checkpoint,
            specs,
            threshold,
            required_groups,
            cache_key=cache_name,
            state_key=frozenset(),
            order_hint=index.checkpoint_order,
        )
    else:
        # Only held identity/revocation records change semantic replay.  Held
        # votes can remain in the cached state and are skipped by tally(), so
        # the cache key is the small set of blocked modifiers, not all holds.
        prefix_ids = index.checkpoint - blocked_modifiers
        base_state, base_order = cache.get(
            index,
            prefix_ids,
            specs,
            threshold,
            required_groups,
            cache_key=cache_name,
            state_key=frozenset(("modifiers", frozenset(blocked_modifiers))),
            order_builder=lambda: [eid for eid in index.checkpoint_order if eid not in blocked_modifiers],
        )

    window_ids = [eid for eid in resolve_window_ids(index, candidate) if eid not in blocked_set]
    return {
        "closure": closure,
        "specs": specs,
        "window_ids": window_ids,
        "base_state": base_state,
        "base_order": base_order,
        "threshold": threshold,
        "required_groups": required_groups,
        "blocked": blocked_set,
    }


def explore(
    index: CaseIndex,
    candidate: dict[str, Any],
    prepared: dict[str, Any],
    stop_after_first_pass: bool = False,
) -> dict[str, Any]:
    specs = prepared["specs"]
    win_ids: list[str] = prepared["window_ids"]
    base_state: EngineState = prepared["base_state"]
    threshold = prepared["threshold"]
    required_groups = prepared["required_groups"]
    blocked: set[str] = prepared.get("blocked") or set()

    if len(win_ids) > 20:
        # The documented ambiguity bound is 16; leave a small implementation
        # margin while preventing accidental factorial explosions.
        raise ValueError(f"ambiguous analysis window has {len(win_ids)} events; maximum supported is 20")

    bit = {eid: i for i, eid in enumerate(win_ids)}
    n = len(win_ids)
    full_mask = (1 << n) - 1
    pred_mask: list[int] = [0] * n
    for eid in win_ids:
        m = 0
        for p in index.preds[eid]:
            if p in bit:
                m |= 1 << bit[p]
        pred_mask[bit[eid]] = m

    visited: set[tuple[Any, ...]] = set()
    pass_path: list[str] | None = None
    reject_path: list[str] | None = None
    state_count = 0
    terminal_states = 0
    pass_terminal_states = 0
    fail_terminal_states = 0

    def dfs(mask: int, state: EngineState, path: list[str]) -> bool:
        nonlocal pass_path, reject_path, state_count, terminal_states, pass_terminal_states, fail_terminal_states
        key = state.key(mask)
        if key in visited:
            return False
        visited.add(key)
        state_count += 1

        current = tally_state(state, specs, threshold, required_groups, blocked)
        if current["passed"] and pass_path is None:
            pass_path = path.copy()

        if mask == full_mask:
            terminal_states += 1
            if current["passed"]:
                pass_terminal_states += 1
            else:
                fail_terminal_states += 1
                if reject_path is None:
                    reject_path = path.copy()
            return current["passed"]

        found_pass_here = current["passed"]
        if stop_after_first_pass and found_pass_here:
            return True

        available: list[int] = []
        for i in range(n):
            if not (mask >> i) & 1 and (pred_mask[i] & ~mask) == 0:
                available.append(i)
        available.sort(key=lambda i: win_ids[i])

        branch_pass = found_pass_here
        for i in available:
            eid = win_ids[i]
            nxt = state.clone()
            apply_event(index, nxt, eid, specs)
            path.append(eid)
            result = dfs(mask | (1 << i), nxt, path)
            path.pop()
            branch_pass = branch_pass or result
            if stop_after_first_pass and result:
                return True
        return branch_pass

    initial = base_state.clone()
    base_tally = tally_state(initial, specs, threshold, required_groups, blocked)
    if base_tally["passed"]:
        pass_path = []
    dfs(0, initial, [])

    pass_witness = None
    if pass_path is not None:
        state, steps, tally = replay_order(index, pass_path, specs, threshold, required_groups, base_state, blocked)
        pass_witness = {
            "checkpoint_prefix_order": prepared["base_order"],
            "post_checkpoint_order": pass_path,
            "complete_review_prefix": prepared["base_order"] + pass_path,
            "steps": steps,
            "tally": tally,
            "causal_closed": True,
        }

    reject_witness = None
    if reject_path is not None:
        state, steps, tally = replay_order(index, reject_path, specs, threshold, required_groups, base_state, blocked)
        reject_witness = {
            "checkpoint_prefix_order": prepared["base_order"],
            "post_checkpoint_order": reject_path,
            "complete_review_prefix": prepared["base_order"] + reject_path,
            "steps": steps,
            "tally": tally,
            "causal_closed": True,
            "terminal_full_window": True,
        }

    pass_exists = pass_witness is not None
    if prepared["closure"]["status"] != "resolved":
        verdict = "never_releasable"
        code = "NO"
    elif pass_exists and fail_terminal_states > 0:
        verdict = "order_dependent"
        code = "CASE"
    elif pass_exists and fail_terminal_states == 0:
        verdict = "always_releasable"
        code = "YES"
    else:
        verdict = "never_releasable"
        code = "NO"

    return {
        "verdict": verdict,
        "certify": code,
        "pass_exists": pass_exists,
        "state_space": {
            "reachable_semantic_states": state_count,
            "terminal_states": terminal_states,
            "passing_terminal_states": pass_terminal_states,
            "failing_terminal_states": fail_terminal_states,
            "window_event_count": n,
        },
        "pass_witness": pass_witness,
        "reject_witness": reject_witness,
        "base_tally": base_tally,
    }


def has_any_pass(
    index: CaseIndex,
    candidate: dict[str, Any],
    blocked: set[str] | frozenset[str] | None = None,
    base_cache: BaseCache | None = None,
) -> bool:
    prepared = prepare_analysis(index, candidate, blocked, base_cache)
    if prepared["closure"]["status"] != "resolved":
        return False
    result = explore(index, candidate, prepared, stop_after_first_pass=True)
    return bool(result["pass_exists"])


def certify_candidate(
    index: CaseIndex,
    candidate_id: str,
    blocked: set[str] | frozenset[str] | None = None,
    base_cache: BaseCache | None = None,
) -> dict[str, Any]:
    candidate = index.candidate_by_id[candidate_id]
    prepared = prepare_analysis(index, candidate, blocked, base_cache)
    if prepared["closure"]["status"] != "resolved":
        return {
            "candidate_id": candidate_id,
            "artifact_id": candidate.get("artifact_id"),
            "phase": candidate.get("phase"),
            "verdict": "never_releasable",
            "certify": "NO",
            "pass_exists": False,
            "closure": prepared["closure"],
            "blocked_event_ids": sorted(blocked or []),
        }
    result = explore(index, candidate, prepared, stop_after_first_pass=False)
    return {
        "candidate_id": candidate_id,
        "artifact_id": candidate.get("artifact_id"),
        "artifact_digest": candidate.get("artifact_digest", candidate.get("digest")),
        "phase": candidate.get("phase"),
        "mandatory": bool(candidate.get("mandatory", False)),
        "closure": {k: v for k, v in prepared["closure"].items() if k not in ("nodes", "edges")},
        "threshold": prepared["threshold"],
        "required_independent_groups": prepared["required_groups"],
        "blocked_event_ids": sorted(blocked or []),
        **result,
    }
