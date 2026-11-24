"""Offline synthetic fixtures, including the required dual-revocation case."""
from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

from .caseio import CaseIndex
from .closures import dependency_closure


def _event(eid: str, kind: str, **fields: Any) -> dict[str, Any]:
    out = {"id": eid, "kind": kind}
    out.update(fields)
    return out


def sample_case() -> dict[str, Any]:
    build_log = [
        _event("build-core-v1", "artifact_built", artifact_id="lib-core", digest="sha256:core-v1", dependencies=[]),
        _event(
            "build-util-v1",
            "artifact_built",
            artifact_id="lib-util",
            digest="sha256:util-v1",
            dependencies=[{"artifact_id": "lib-core", "digest": "sha256:core-v1"}],
        ),
        _event(
            "build-combo-v1",
            "artifact_built",
            artifact_id="art-combo",
            digest="sha256:combo-v1",
            dependencies=[{"artifact_id": "lib-util", "digest": "sha256:util-v1"}],
        ),
        _event(
            "build-safe-v1",
            "artifact_built",
            artifact_id="art-safe",
            digest="sha256:safe-v1",
            dependencies=[{"artifact_id": "lib-core", "digest": "sha256:core-v1"}],
        ),
        _event("build-alias-v1", "artifact_built", artifact_id="art-alias", digest="sha256:alias-v1", dependencies=[]),
        _event("build-denied-v1", "artifact_built", artifact_id="art-denied", digest="sha256:denied-v1", dependencies=[]),
        # A mutable tag movement is recorded but never used as object identity;
        # candidates pin artifact_id + immutable digest.
        _event(
            "tag-move-release",
            "tag_move",
            tag="release-current",
            from_artifact_id="art-older",
            from_digest="sha256:older-v1",
            to_artifact_id="art-safe",
            to_digest="sha256:safe-v1",
        ),
    ]

    approval_log: list[dict[str, Any]] = [
        # Stable natural-person/alias facts in the locked prefix.
        _event("id-alice", "alias_binding", auth_ref="key-alice", person_id="p-alice"),
        _event("id-bob", "alias_binding", auth_ref="key-bob", person_id="p-bob"),
        _event("id-carol", "alias_binding", auth_ref="key-carol", person_id="p-carol"),
        _event("id-dave", "alias_binding", auth_ref="key-dave", person_id="p-dave"),
        _event("id-robin-old", "alias_binding", auth_ref="key-roving", person_id="p-robin"),
        _event("id-anchor", "alias_binding", auth_ref="key-anchor", person_id="p-anchor"),

        # Combo anchors: two persons and two independently administered groups.
        # The two groups deliberately reuse the same display name: names are
        # not identity; group_id/independence_key are.
        _event(
            "vote-alice", "vote", _candidate="rc-combo", phase="ga", auth_ref="key-alice",
            group_id="grp-release-a", group_name="Release Approvers", independence_key="ind-release-a",
        ),
        _event(
            "vote-bob", "vote", _candidate="rc-combo", phase="ga", auth_ref="key-bob",
            group_id="grp-release-b", group_name="Release Approvers", independence_key="ind-release-b",
        ),

        # Alias-move candidate anchor.
        _event(
            "vote-alias-anchor", "vote", _candidate="rc-alias", phase="identity", auth_ref="key-anchor",
            group_id="grp-identity-a", independence_key="ind-identity-a",
        ),

        # Safe/mandatory candidate: four stable votes, three suffice and both
        # independent groups remain represented.
        _event("sv1", "vote", _candidate="rc-safe", phase="ga", person_id="p-safe1", group_id="grp-safe-a", independence_key="ind-safe-a"),
        _event("sv2", "vote", _candidate="rc-safe", phase="ga", person_id="p-safe2", group_id="grp-safe-b", independence_key="ind-safe-b"),
        _event("sv3", "vote", _candidate="rc-safe", phase="ga", person_id="p-safe3", group_id="grp-safe-a", independence_key="ind-safe-a"),
        _event("sv4", "vote", _candidate="rc-safe", phase="ga", person_id="p-safe4", group_id="grp-safe-b", independence_key="ind-safe-b"),

        # Denied candidate has only one group/person.
        _event("dv1", "vote", _candidate="rc-denied", phase="ga", person_id="p-denied1", group_id="grp-denied-a", independence_key="ind-denied-a"),

        # Ambiguous window 1: two independent temporary revocation races.
        _event("revoke-carol", "revocation", action="revoke", target_type="person", target_id="p-carol"),
        _event(
            "vote-carol", "vote", _candidate="rc-combo", phase="ga", auth_ref="key-carol",
            group_id="grp-release-a", group_name="Release Approvers", independence_key="ind-release-a",
        ),
        _event("restore-carol", "revocation", action="restore", target_type="person", target_id="p-carol", predecessors=["revoke-carol"]),

        _event("revoke-dave", "revocation", action="revoke", target_type="person", target_id="p-dave"),
        _event(
            "vote-dave", "vote", _candidate="rc-combo", phase="ga", auth_ref="key-dave",
            group_id="grp-release-b", group_name="Release Approvers", independence_key="ind-release-b",
        ),
        _event("restore-dave", "revocation", action="restore", target_type="person", target_id="p-dave", predecessors=["revoke-dave"]),

        # Ambiguous window 2: a mutable alias/label moves between natural persons.
        _event("alias-move-mallory", "alias_binding", auth_ref="key-roving", person_id="p-mallory"),
        _event(
            "vote-roving", "vote", _candidate="rc-alias", phase="identity", auth_ref="key-roving", person_id="p-robin",
            group_id="grp-identity-b", independence_key="ind-identity-b",
        ),
    ]

    combo_window = ["revoke-carol", "vote-carol", "restore-carol", "revoke-dave", "vote-dave", "restore-dave"]
    alias_window = ["alias-move-mallory", "vote-roving"]
    window_ids = set(combo_window + alias_window)

    candidates = [
        {"id": "rc-combo", "artifact_id": "art-combo", "artifact_digest": "sha256:combo-v1", "phase": "ga", "window_id": "w-two-revocations"},
        {"id": "rc-alias", "artifact_id": "art-alias", "artifact_digest": "sha256:alias-v1", "phase": "identity", "window_id": "w-alias-move"},
        {"id": "rc-safe", "artifact_id": "art-safe", "artifact_digest": "sha256:safe-v1", "phase": "ga", "mandatory": True},
        {"id": "rc-denied", "artifact_id": "art-denied", "artifact_digest": "sha256:denied-v1", "phase": "ga"},
    ]

    pause_points = [
        {"id": "pp01-hold-carol-vote", "downtime_minutes": 3, "hold_events": ["vote-carol"]},
        {"id": "pp02-hold-dave-vote", "downtime_minutes": 4, "hold_events": ["vote-dave"]},
        {"id": "pp03-hold-roving-vote", "downtime_minutes": 2, "hold_events": ["vote-roving"]},
        {"id": "pp04-freeze-combo-votes", "downtime_minutes": 6, "hold_events": ["vote-carol", "vote-dave"]},
        {"id": "pp05-freeze-alias-receipt", "downtime_minutes": 2, "hold_events": ["vote-roving", "alias-move-mallory"]},
        {"id": "pp06-freeze-all-contested", "downtime_minutes": 10, "hold_events": ["vote-carol", "vote-dave", "vote-roving"]},
        {"id": "pp07-hold-carol-identity", "downtime_minutes": 7, "hold_events": ["id-carol"]},
        {"id": "pp08-hold-dave-identity", "downtime_minutes": 7, "hold_events": ["id-dave"]},
        {"id": "pp09-hold-roving-old-identity", "downtime_minutes": 3, "hold_events": ["id-robin-old"]},
        {"id": "pp10-revocation-feed", "downtime_minutes": 8, "hold_events": ["revoke-carol", "revoke-dave"], "note": "Removes adverse revocations; intentionally not protective."},
        {"id": "pp11-combo-anchors", "downtime_minutes": 9, "hold_events": ["vote-alice", "vote-bob"]},
        {"id": "pp12-global-vote-gate", "downtime_minutes": 1, "hold_events": ["vote-alice", "vote-bob", "vote-carol", "vote-dave", "vote-roving", "sv1", "sv2", "sv3", "sv4", "dv1"]},
        {"id": "pp13-safe-redundant-vote", "downtime_minutes": 1, "hold_events": ["sv4"], "note": "Still leaves three safe votes."},
        {"id": "pp14-build-heartbeat", "downtime_minutes": 1, "hold_events": ["build-core-v1"], "note": "Would block safe closure too, but does not cover uncertain candidates."},
        {"id": "pp15-denied-receipt", "downtime_minutes": 2, "hold_events": ["dv1"]},
        {"id": "pp16-contested-bundle", "downtime_minutes": 7, "hold_events": ["vote-carol", "vote-dave", "vote-roving"]},
    ]

    raw: dict[str, Any] = {
        "schema": "splitrelease.case/v1",
        "case_id": "synthetic-dual-revocation-case",
        "description": "Two independent revocation races; either adverse race alone passes, both together fail.",
        "phases": {
            "ga": {"threshold": 3, "required_independent_groups": 2},
            "identity": {"threshold": 2, "required_independent_groups": 2},
        },
        "logs": {"build_log": build_log, "approval_log": approval_log},
        "checkpoint": {
            "checkpoint_id": "cp-bilateral-0001",
            "confirmed": True,
            "build_prefix": [e["id"] for e in build_log],
            "approval_prefix": [e["id"] for e in approval_log if e["id"] not in window_ids],
        },
        "windows": [
            {"id": "w-two-revocations", "event_ids": combo_window, "max_events_documented": 16},
            {"id": "w-alias-move", "event_ids": alias_window, "max_events_documented": 16},
        ],
        "candidates": candidates,
        "pause_points": pause_points,
    }
    return _bind_candidate_closure_digests(raw)


def _bind_candidate_closure_digests(raw: dict[str, Any]) -> dict[str, Any]:
    """Compute canonical closure digests and stamp synthetic votes."""
    index = CaseIndex(copy.deepcopy(raw))
    digest_by_candidate: dict[str, str] = {}
    for c in raw["candidates"]:
        closure = dependency_closure(index, c)
        if closure["status"] != "resolved":
            raise AssertionError(closure)
        digest_by_candidate[c["id"]] = closure["closure_digest"]

    for log_name in ("build_log", "approval_log"):
        for event in raw["logs"][log_name]:
            cid = event.pop("_candidate", None)
            if cid is not None:
                event["closure_digest"] = digest_by_candidate[cid]
    return raw


def topo_small_case() -> dict[str, Any]:
    """A tiny standalone case used by exhaustive topological-order diff tests."""
    raw = sample_case()
    raw["case_id"] = "topo-small-dual-revocation"
    raw["candidates"] = [c for c in raw["candidates"] if c["id"] == "rc-combo"]
    raw["pause_points"] = []
    return raw


def large_case(total_events: int = 100_000) -> dict[str, Any]:
    raw = sample_case()
    existing = len(raw["logs"]["build_log"]) + len(raw["logs"]["approval_log"])
    needed = max(0, total_events - existing)
    last_build: str | None = None
    last_approval: str | None = None
    build_prefix = raw["checkpoint"]["build_prefix"]
    approval_prefix = raw["checkpoint"]["approval_prefix"]

    for i in range(needed):
        eid = f"noise-{i:06d}"
        if i % 2 == 0:
            preds = [last_build] if last_build is not None and i % 100 == 0 else []
            # Sparse predecessor chains keep ordinary causal indexing exercised
            # without making every event a single giant chain.
            event = _event(eid, "heartbeat", source_stream="build", sequence=i, predecessors=preds)
            raw["logs"]["build_log"].append(event)
            build_prefix.append(eid)
            if preds:
                last_build = eid
            elif i % 100 == 0:
                last_build = eid
        else:
            preds = [last_approval] if last_approval is not None and i % 100 == 1 else []
            event = _event(eid, "audit_note", source_stream="approval", sequence=i, predecessors=preds)
            raw["logs"]["approval_log"].append(event)
            approval_prefix.append(eid)
            if preds:
                last_approval = eid
            elif i % 100 == 1:
                last_approval = eid
    raw["case_id"] = f"large-{total_events}-log-performance-case"
    return raw


def write_fixture(kind: str, out: str | Path) -> Path:
    if kind == "sample":
        raw = sample_case()
    elif kind == "topo-small":
        raw = topo_small_case()
    elif kind == "large":
        raw = large_case(100_000)
    else:
        raise ValueError(f"unknown fixture kind {kind}")
    path = Path(out)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(raw, ensure_ascii=False, indent=2), encoding="utf-8")
    return path
