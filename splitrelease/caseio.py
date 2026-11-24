"""UTF-8 JSON case loading, validation and causal-DAG indexing.

File/array line order is never used as causality.  Only explicit
``predecessors`` edges and the confirmed checkpoint prefix sets matter.
"""
from __future__ import annotations

import heapq
import json
from pathlib import Path
from typing import Any, Iterable

from . import SCHEMA


class CaseError(ValueError):
    """Raised when a splitrelease case violates the documented format."""


class CaseIndex:
    def __init__(self, raw: dict[str, Any], source_path: str | None = None):
        if not isinstance(raw, dict):
            raise CaseError("top-level JSON value must be an object")
        self.raw = raw
        self.source_path = source_path
        self.schema = raw.get("schema", SCHEMA)

        self.events: dict[str, dict[str, Any]] = {}
        self.source_of: dict[str, str] = {}
        self.build_log: list[dict[str, Any]] = []
        self.approval_log: list[dict[str, Any]] = []

        logs = raw.get("logs", raw)
        if not isinstance(logs, dict):
            raise CaseError("'logs' must be an object")
        build_events = logs.get("build_log", logs.get("artifact_log", []))
        approval_events = logs.get("approval_log", [])
        if not isinstance(build_events, list) or not isinstance(approval_events, list):
            raise CaseError("logs.build_log and logs.approval_log must be arrays")

        self._ingest_log(build_events, "build", self.build_log)
        self._ingest_log(approval_events, "approval", self.approval_log)

        self.preds: dict[str, list[str]] = {eid: [] for eid in self.events}
        self.succ: dict[str, list[str]] = {eid: [] for eid in self.events}
        for eid, event in self.events.items():
            preds = event.get("predecessors", [])
            if preds is None:
                preds = []
            if not isinstance(preds, list):
                raise CaseError(f"event {eid!r}: predecessors must be an array")
            seen = set()
            for p in preds:
                if not isinstance(p, str) or not p:
                    raise CaseError(f"event {eid!r}: predecessor ids must be non-empty strings")
                if p == eid:
                    raise CaseError(f"event {eid!r}: self predecessor is forbidden")
                if p not in self.events:
                    raise CaseError(f"event {eid!r}: unknown predecessor {p!r}")
                if p not in seen:
                    seen.add(p)
                    self.preds[eid].append(p)
                    self.succ[p].append(eid)

        self.topo_order = topological_order(set(self.events), self.preds)

        cp = raw.get("checkpoint", {})
        if not isinstance(cp, dict):
            raise CaseError("'checkpoint' must be an object")
        if "confirmed" in cp and cp.get("confirmed") is not True:
            raise CaseError("checkpoint must be a confirmed bilateral checkpoint")
        build_prefix = cp.get("build_prefix", cp.get("build", []))
        approval_prefix = cp.get("approval_prefix", cp.get("approval", []))
        self.checkpoint_build = self._prefix_set(build_prefix, "build")
        self.checkpoint_approval = self._prefix_set(approval_prefix, "approval")
        self.checkpoint = self.checkpoint_build | self.checkpoint_approval
        self._validate_checkpoint_closure()
        # Restricting a topological order remains topological; this gives a
        # fast canonical replay order for 100k-event locked prefixes.
        self.checkpoint_order = [eid for eid in self.topo_order if eid in self.checkpoint]

        self.phases = raw.get("phases", {})
        if not isinstance(self.phases, dict):
            raise CaseError("'phases' must be an object")
        self.candidates = raw.get("candidates", [])
        if not isinstance(self.candidates, list):
            raise CaseError("'candidates' must be an array")
        self.candidate_by_id: dict[str, dict[str, Any]] = {}
        for c in self.candidates:
            if not isinstance(c, dict) or not isinstance(c.get("id"), str):
                raise CaseError("every candidate needs a string 'id'")
            cid = c["id"]
            if cid in self.candidate_by_id:
                raise CaseError(f"duplicate candidate id {cid!r}")
            inline_window = c.get("ambiguous_event_ids")
            if isinstance(inline_window, list) and len(inline_window) > 16:
                raise CaseError(f"candidate {cid!r}: ambiguous_event_ids exceeds 16-event window bound")
            self.candidate_by_id[cid] = c

        self.windows = {w["id"]: w for w in raw.get("windows", []) if isinstance(w, dict) and "id" in w}
        for wid, w in self.windows.items():
            ids = w.get("event_ids", [])
            if not isinstance(ids, list) or any(x not in self.events for x in ids if isinstance(x, str)):
                raise CaseError(f"window {wid!r} has invalid event_ids")
            if len(ids) > 16:
                raise CaseError(f"window {wid!r} has {len(ids)} events; documented ambiguity limit is 16")

        self.pause_points = raw.get("pause_points", [])
        if not isinstance(self.pause_points, list):
            raise CaseError("'pause_points' must be an array")
        self.pause_by_id: dict[str, dict[str, Any]] = {}
        for p in self.pause_points:
            if not isinstance(p, dict) or not isinstance(p.get("id"), str):
                raise CaseError("every pause point needs a string 'id'")
            pid = p["id"]
            if pid in self.pause_by_id:
                raise CaseError(f"duplicate pause point id {pid!r}")
            holds = p.get("hold_events", [])
            if not isinstance(holds, list) or any(h not in self.events for h in holds if isinstance(h, str)):
                raise CaseError(f"pause point {pid!r} has invalid hold_events")
            cost = p.get("downtime_minutes", 0)
            if not isinstance(cost, (int, float)) or isinstance(cost, bool) or cost < 0:
                raise CaseError(f"pause point {pid!r}: downtime_minutes must be a non-negative number")
            self.pause_by_id[pid] = p

        # Semantic indexes.  Building them once keeps 100k-log cases linear.
        self.build_by_artifact_digest: dict[tuple[str, str], str] = {}
        for eid, e in self.events.items():
            if self.source_of[eid] == "build" and e.get("kind") in ("artifact_built", "artifact", "build_record"):
                aid = e.get("artifact_id")
                digest = e.get("digest")
                if isinstance(aid, str) and isinstance(digest, str):
                    self.build_by_artifact_digest[(aid, digest)] = eid

        self.alias_by_ref: dict[str, list[str]] = {}
        self.alias_by_person: dict[str, list[str]] = {}
        self.revocation_by_target: dict[tuple[str, str], list[str]] = {}
        self.vote_index: dict[tuple[str, str], list[str]] = {}
        for eid, e in self.events.items():
            kind = e.get("kind")
            if kind in ("alias_binding", "person_alias", "alias"):
                ref = e.get("auth_ref", e.get("alias", e.get("ref")))
                pid = e.get("person_id")
                if isinstance(ref, str):
                    self.alias_by_ref.setdefault(ref, []).append(eid)
                if isinstance(pid, str):
                    self.alias_by_person.setdefault(pid, []).append(eid)
            elif kind in ("revocation", "revoke", "suspension"):
                ttype = e.get("target_type", e.get("subject_type", "person"))
                tid = e.get("target_id", e.get("subject_id"))
                if isinstance(tid, str):
                    self.revocation_by_target.setdefault((str(ttype), tid), []).append(eid)
            elif kind in ("vote", "approval_receipt", "approval", "receipt"):
                cd = e.get("closure_digest", e.get("dependency_closure_digest"))
                phase = e.get("phase", "")
                if isinstance(cd, str):
                    self.vote_index.setdefault((cd, str(phase)), []).append(eid)
                    if phase:
                        self.vote_index.setdefault((cd, ""), []).append(eid)

    def _ingest_log(self, events: list[Any], source: str, sink: list[dict[str, Any]]) -> None:
        for position, event in enumerate(events):
            if not isinstance(event, dict):
                raise CaseError(f"{source}_log[{position}] must be an object")
            eid = event.get("id")
            if not isinstance(eid, str) or not eid:
                raise CaseError(f"{source}_log[{position}] needs a non-empty string 'id'")
            if eid in self.events:
                raise CaseError(f"duplicate event id {eid!r}")
            event = dict(event)
            event.setdefault("kind", "note")
            event["_source"] = source
            self.events[eid] = event
            self.source_of[eid] = source
            sink.append(event)

    def _prefix_set(self, ids: Any, source: str) -> set[str]:
        if not isinstance(ids, list):
            raise CaseError(f"checkpoint {source}_prefix must be an array")
        result: set[str] = set()
        for eid in ids:
            if not isinstance(eid, str) or eid not in self.events:
                raise CaseError(f"checkpoint prefix id {eid!r} is not a known event")
            if self.source_of[eid] != source:
                raise CaseError(f"checkpoint prefix id {eid!r} is not in {source}_log")
            result.add(eid)
        return result

    def _validate_checkpoint_closure(self) -> None:
        for eid in self.checkpoint:
            for p in self.preds[eid]:
                if p not in self.checkpoint:
                    raise CaseError(
                        f"checkpoint prefix is not causally closed: {eid!r} requires {p!r}"
                    )

    def phase_policy(self, phase: str | None) -> tuple[int, int]:
        p = self.phases.get(phase or "", {})
        if not isinstance(p, dict):
            p = {}
        threshold = int(p.get("threshold", self.raw.get("default_threshold", 2)))
        groups = int(p.get("required_independent_groups", p.get("independent_groups", 2)))
        if threshold < 0 or groups < 0:
            raise CaseError("thresholds must be non-negative")
        return threshold, groups

    def ancestor_closure(self, ids: Iterable[str]) -> set[str]:
        result: set[str] = set()
        stack = [x for x in ids if x in self.events]
        while stack:
            x = stack.pop()
            if x in result:
                continue
            result.add(x)
            stack.extend(self.preds[x])
        return result

    def descendant_closure(self, ids: Iterable[str]) -> set[str]:
        result: set[str] = set()
        stack = [x for x in ids if x in self.events]
        while stack:
            x = stack.pop()
            if x in result:
                continue
            result.add(x)
            stack.extend(self.succ[x])
        return result


def load_case(path: str | Path) -> CaseIndex:
    path = Path(path)
    try:
        with path.open("r", encoding="utf-8-sig") as f:
            raw = json.load(f)
    except json.JSONDecodeError as exc:
        raise CaseError(f"invalid UTF-8 JSON in {path}: {exc}") from exc
    except OSError as exc:
        raise CaseError(str(exc)) from exc
    return CaseIndex(raw, str(path))


def topological_order(ids: set[str], preds: dict[str, list[str]]) -> list[str]:
    """Kahn order with id heap only for deterministic reporting.

    The id tie-break is not treated as evidence; all tied orders are explored
    by the certification engine.
    """
    idset = set(ids)
    remaining_preds = {eid: [p for p in preds.get(eid, []) if p in idset] for eid in idset}
    indeg = {eid: len(remaining_preds[eid]) for eid in idset}
    children: dict[str, list[str]] = {eid: [] for eid in idset}
    for eid, ps in remaining_preds.items():
        for p in ps:
            children[p].append(eid)
    ready = [eid for eid, d in indeg.items() if d == 0]
    heapq.heapify(ready)
    out: list[str] = []
    while ready:
        eid = heapq.heappop(ready)
        out.append(eid)
        for child in children[eid]:
            indeg[child] -= 1
            if indeg[child] == 0:
                heapq.heappush(ready, child)
    if len(out) != len(idset):
        cycle = sorted(eid for eid, d in indeg.items() if d > 0)
        raise CaseError(f"causal predecessor cycle or missing closure near {cycle}")
    return out


def legal_topological_orders(ids: Iterable[str], preds: dict[str, list[str]]) -> list[list[str]]:
    """Naive full topological-order enumeration, used by differential tests."""
    idset = list(ids)
    target = set(idset)
    local_preds = {eid: [p for p in preds.get(eid, []) if p in target] for eid in idset}
    results: list[list[str]] = []

    def available(chosen: set[str], remaining: list[str]) -> list[str]:
        return [eid for eid in remaining if all(p in chosen for p in local_preds[eid])]

    def rec(remaining: list[str], chosen: set[str], path: list[str]) -> None:
        if not remaining:
            results.append(path.copy())
            return
        for eid in available(chosen, remaining):
            chosen.add(eid)
            path.append(eid)
            rec([x for x in remaining if x != eid], chosen, path)
            path.pop()
            chosen.remove(eid)

    rec(idset, set(), [])
    return results
