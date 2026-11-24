"""Minimum self-contained evidence certificates for always-safe candidates."""
from __future__ import annotations

from typing import Any

from .caseio import CaseIndex
from .engine import BaseCache, explore


def semantic_closure_for_vote(index: CaseIndex, vote_id: str) -> set[str]:
    """All identity/revocation records that could affect one receipt.

    Including this adversarial closure means an omitted event cannot change the
    receipt's natural-person attribution or suspension status.
    """
    event_ids: set[str] = {vote_id}
    refs: set[str] = set()
    persons: set[str] = set()
    vote_targets: set[str] = {vote_id}
    # A label movement that is causally after the receipt cannot change the
    # person attribution frozen at receipt position.  Later revocations can
    # still affect endpoint validity and are therefore not filtered here.
    strict_descendants = index.descendant_closure([vote_id]) - {vote_id}

    def absorb(eid: str) -> None:
        e = index.events[eid]
        kind = e.get("kind")
        ref = e.get("auth_ref", e.get("alias", e.get("ref")))
        if isinstance(ref, str):
            refs.add(ref)
        pid = e.get("person_id")
        if isinstance(pid, str):
            persons.add(pid)
        if kind in ("revocation", "revoke", "suspension"):
            ttype = str(e.get("target_type", e.get("subject_type", "person")))
            tid = e.get("target_id", e.get("subject_id"))
            if isinstance(tid, str):
                if ttype == "vote":
                    vote_targets.add(tid)
                else:
                    persons.add(tid)

    changed = True
    while changed:
        before = (len(event_ids), len(refs), len(persons), len(vote_targets))
        for eid in list(event_ids):
            absorb(eid)
        for ref in refs:
            for alias_id in index.alias_by_ref.get(ref, ()):
                if alias_id in strict_descendants:
                    continue
                event_ids.add(alias_id)
        for pid in persons:
            event_ids.update(e for e in index.revocation_by_target.get(("person", pid), ()))
        for vid in vote_targets:
            event_ids.update(e for e in index.revocation_by_target.get(("vote", vid), ()))
            # A targeted vote itself must be present if a revocation names it.
            if vid in index.events:
                event_ids.add(vid)
        changed = before != (len(event_ids), len(refs), len(persons), len(vote_targets))

    return event_ids


def closed_evidence_set(
    index: CaseIndex,
    build_event_ids: set[str],
    vote_ids: set[str],
) -> set[str]:
    roots = set(build_event_ids) | set(vote_ids)
    for vid in vote_ids:
        roots.update(semantic_closure_for_vote(index, vid))
    return index.ancestor_closure(roots)


def _bundle_report(
    index: CaseIndex,
    candidate: dict[str, Any],
    closure_info: dict[str, Any],
    specs: dict[str, dict[str, Any]],
    evidence_ids: set[str],
    cache: BaseCache,
) -> dict[str, Any]:
    threshold, required_groups = index.phase_policy(candidate.get("phase"))
    prefix_ids = evidence_ids & index.checkpoint
    # Include every post-checkpoint event, including build/note intermediates.
    # They do not mutate approval state but preserve transitive predecessor
    # constraints during topological replay.
    post_ids = [eid for eid in evidence_ids - index.checkpoint]
    state, order = cache.get(
        index,
        prefix_ids,
        specs,
        threshold,
        required_groups,
        cache_key="evidence:" + str(candidate.get("id")) + ":" + closure_info["closure_digest"],
    )
    prepared = {
        "closure": closure_info,
        "specs": specs,
        "window_ids": post_ids,
        "base_state": state,
        "base_order": order,
        "threshold": threshold,
        "required_groups": required_groups,
    }
    return explore(index, candidate, prepared, stop_after_first_pass=False)


def find_minimal_evidence(
    index: CaseIndex,
    candidate: dict[str, Any],
    certification: dict[str, Any],
) -> dict[str, Any] | None:
    if certification.get("verdict") != "always_releasable":
        return None

    cid = str(candidate["id"])
    closure_info = certification.get("closure_full")
    if closure_info is None:
        # certify_candidate strips heavy closure fields; caller may attach it.
        from .closures import dependency_closure

        closure_info = dependency_closure(index, candidate)
    if closure_info.get("status") != "resolved":
        return None

    from .engine import candidate_vote_specs

    specs = candidate_vote_specs(index, candidate, closure_info["closure_digest"])
    vote_ids = sorted(vid for vid, spec in specs.items() if spec.get("static_ok"))
    build_ids = set(closure_info.get("record_event_ids", []))

    e0 = closed_evidence_set(index, build_ids, set())
    individual: dict[str, set[str]] = {vid: closed_evidence_set(index, build_ids, {vid}) for vid in vote_ids}
    all_ids = set(e0)
    for vid in vote_ids:
        all_ids |= individual[vid]

    cache = BaseCache()
    safe_cache: dict[tuple[str, ...], dict[str, Any]] = {}

    def check(votes: tuple[str, ...], eids: set[str]) -> dict[str, Any] | None:
        key = tuple(sorted(eids))
        if key in safe_cache:
            report = safe_cache[key]
        else:
            report = _bundle_report(index, candidate, closure_info, specs, eids, cache)
            safe_cache[key] = report
        if report.get("verdict") == "always_releasable":
            return report
        return None

    all_votes = tuple(vote_ids)
    all_report = check(all_votes, all_ids)
    if all_report is None:
        # Should be impossible when the full case is always safe; fail closed
        # rather than inventing a certificate.
        return {
            "minimal_event_count": None,
            "event_ids": sorted(all_ids),
            "error": "evidence closure could not reproduce universal safety",
        }

    best_votes = all_votes
    best_ids = set(all_ids)
    best_key = (len(best_ids), tuple(sorted(best_ids)))
    best_report = all_report

    # Greedy tightened upper bound.
    greedy: list[str] = []
    greedy_ids = set(e0)
    remaining = set(vote_ids)
    while remaining:
        safe_report = check(tuple(greedy), greedy_ids) if greedy else None
        if safe_report is not None:
            break
        choice = min(remaining, key=lambda v: (len(greedy_ids | individual[v]), v))
        greedy.append(choice)
        remaining.remove(choice)
        greedy_ids |= individual[choice]
    greedy_report = check(tuple(greedy), greedy_ids)
    if greedy_report is not None:
        gkey = (len(greedy_ids), tuple(sorted(greedy_ids)))
        if gkey < best_key:
            best_votes = tuple(greedy)
            best_ids = set(greedy_ids)
            best_key = gkey
            best_report = greedy_report

    def dfs(start: int, current_ids: set[str], selected: list[str]) -> None:
        nonlocal best_votes, best_ids, best_key, best_report
        for i in range(start, len(vote_ids)):
            vid = vote_ids[i]
            new_ids = current_ids | individual[vid]
            size = len(new_ids)
            if size > best_key[0]:
                continue
            selected.append(vid)
            votes_key = tuple(selected)
            report = check(votes_key, new_ids)
            if report is not None:
                candidate_key = (size, tuple(sorted(new_ids)))
                if candidate_key < best_key:
                    best_key = candidate_key
                    best_votes = votes_key
                    best_ids = set(new_ids)
                    best_report = report
            elif size < best_key[0]:
                dfs(i + 1, new_ids, selected)
            selected.pop()

    # A build-only bundle is the smallest possible root.
    root_report = check((), e0)
    if root_report is not None:
        best_votes = ()
        best_ids = set(e0)
        best_key = (len(best_ids), tuple(sorted(best_ids)))
        best_report = root_report
    else:
        dfs(0, set(e0), [])

    roots = set(build_ids) | set(best_votes)
    predecessor_only = sorted(best_ids - roots)
    return {
        "minimal_event_count": len(best_ids),
        "event_ids": sorted(best_ids),
        "selected_vote_ids": list(best_votes),
        "build_record_event_ids": sorted(build_ids),
        "causal_predecessor_ids_retained": predecessor_only,
        "tie_break": "minimum event count; then lexicographically smallest sorted event ID tuple",
        "self_containment": (
            "For every selected vote, all order-capable same-auth_ref alias records and "
            "all person/vote revocation records are included, followed by causal predecessors."
        ),
        "universal_replay": {
            "verdict": best_report.get("verdict"),
            "certify": best_report.get("certify"),
            "state_space": best_report.get("state_space"),
            "certifying_witness_tally": best_report.get("pass_witness", {}).get("tally"),
        },
    }
