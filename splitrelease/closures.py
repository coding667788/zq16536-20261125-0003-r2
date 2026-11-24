"""Artifact dependency closure construction and canonical digests."""
from __future__ import annotations

import hashlib
import json
from typing import Any

from .caseio import CaseIndex


def _canonical_digest(payload: dict[str, Any]) -> str:
    blob = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "depclosure-v1:" + hashlib.sha256(blob).hexdigest()


def dependency_closure(index: CaseIndex, candidate: dict[str, Any], blocked: set[str] | frozenset[str] | None = None) -> dict[str, Any]:
    aid = candidate.get("artifact_id")
    digest = candidate.get("artifact_digest", candidate.get("digest"))
    if not isinstance(aid, str) or not isinstance(digest, str):
        return {"status": "unresolved", "reasons": ["candidate requires artifact_id and artifact_digest"]}

    root_event = index.build_by_artifact_digest.get((aid, digest))
    if root_event is None:
        return {"status": "unresolved", "reasons": [f"no immutable build record for {aid}@{digest}"]}
    if blocked is not None and root_event in blocked:
        return {"status": "blocked", "reasons": [f"root build record {root_event} is paused/blocked"]}

    def record_for(a: str, d: str) -> str | None:
        eid = index.build_by_artifact_digest.get((a, d))
        if eid is None:
            return None
        if blocked is not None and eid in blocked:
            return None
        return eid

    root_key = (aid, digest)
    records: dict[tuple[str, str], str] = {root_key: root_event}
    edges: list[list[str]] = []
    missing: list[dict[str, str]] = []
    blocked_records: list[dict[str, str]] = []
    cycle: list[str] | None = None
    color: dict[tuple[str, str], int] = {}
    stack: list[tuple[str, str]] = [root_key]

    while stack:
        key = stack[-1]
        state = color.get(key, 0)
        if state == 0:
            color[key] = 1
            eid = records[key]
            event = index.events[eid]
            deps = event.get("dependencies", event.get("build_dependencies", []))
            if deps is None:
                deps = []
            if not isinstance(deps, list):
                missing.append({"artifact_id": key[0], "digest": key[1], "reason": "dependencies-not-array"})
                stack.pop()
                color[key] = 2
                continue
            child_keys: list[tuple[str, str]] = []
            for dep in deps:
                if isinstance(dep, str) and "@" in dep:
                    da, dd = dep.rsplit("@", 1)
                elif isinstance(dep, dict):
                    da = dep.get("artifact_id", dep.get("id"))
                    dd = dep.get("digest")
                else:
                    continue
                if not isinstance(da, str) or not isinstance(dd, str):
                    continue
                child = (da, dd)
                child_eid = index.build_by_artifact_digest.get(child)
                if child_eid is None:
                    missing.append({"artifact_id": da, "digest": dd, "reason": "missing-build-record"})
                    edges.append([key[0], key[1], da, dd])
                    continue
                if blocked is not None and child_eid in blocked:
                    blocked_records.append({"artifact_id": da, "digest": dd, "event_id": child_eid})
                    edges.append([key[0], key[1], da, dd])
                    continue
                records[child] = child_eid
                edges.append([key[0], key[1], da, dd])
                if color.get(child, 0) == 1:
                    cycle = [key[0], key[1], da, dd]
                elif color.get(child, 0) == 0:
                    child_keys.append(child)
            if cycle is not None:
                break
            for child in reversed(child_keys):
                stack.append(child)
        else:
            color[key] = 2
            stack.pop()

    if cycle is not None:
        return {"status": "unresolved", "reasons": [f"dependency cycle near {cycle}"], "cycle": cycle}
    if missing:
        return {"status": "unresolved", "reasons": ["pinned dependency closure is incomplete"], "missing": missing}
    if blocked_records:
        return {"status": "blocked", "reasons": ["pinned dependency record is held by a pause point"], "blocked": blocked_records}

    nodes = [
        {"artifact_id": a, "digest": d, "record_event_id": records[(a, d)]}
        for a, d in sorted(records)
    ]
    canonical_edges = sorted(edges)
    closure_digest = _canonical_digest({"root": [aid, digest], "nodes": [[n["artifact_id"], n["digest"]] for n in nodes], "edges": canonical_edges})
    return {
        "status": "resolved",
        "artifact_id": aid,
        "artifact_digest": digest,
        "closure_digest": closure_digest,
        "nodes": nodes,
        "edges": canonical_edges,
        "record_event_ids": sorted({n["record_event_id"] for n in nodes}),
    }
