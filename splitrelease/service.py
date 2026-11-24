"""High-level certify and protect use cases."""
from __future__ import annotations

from typing import Any

from .caseio import CaseIndex
from .engine import BaseCache, certify_candidate, has_any_pass
from .evidence import find_minimal_evidence
from .closures import dependency_closure


def certify_case(index: CaseIndex, include_evidence: bool = True) -> dict[str, Any]:
    reports: list[dict[str, Any]] = []
    for candidate in index.candidates:
        cid = candidate["id"]
        report = certify_candidate(index, cid)
        if include_evidence and report.get("verdict") == "always_releasable":
            full_closure = dependency_closure(index, candidate)
            report["closure_full"] = full_closure
            try:
                report["minimal_evidence"] = find_minimal_evidence(index, candidate, report)
            finally:
                report.pop("closure_full", None)
        reports.append(report)

    counts = {"always_releasable": 0, "order_dependent": 0, "never_releasable": 0}
    for r in reports:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    return {
        "schema": "splitrelease.report/v1",
        "case_id": index.raw.get("case_id", "unnamed-case"),
        "summary": {
            "candidate_count": len(reports),
            **counts,
        },
        "candidates": reports,
    }


def _mask_ids(points: list[dict[str, Any]], mask: int) -> list[str]:
    return [p["id"] for i, p in enumerate(points) if mask & (1 << i)]


def plan_protection(index: CaseIndex) -> dict[str, Any]:
    cache = BaseCache()
    reports_by_id = {
        c["id"]: certify_candidate(index, c["id"], base_cache=cache)
        for c in index.candidates
    }
    uncertain = [
        c["id"]
        for c in index.candidates
        if reports_by_id[c["id"]]["verdict"] == "order_dependent"
    ]
    mandatory = [c["id"] for c in index.candidates if c.get("mandatory", False)]

    points = index.pause_points
    n = len(points)
    if n > 20:
        raise ValueError("protect brute-force supports at most 20 proposed pause points")

    effective_blocked: dict[str, set[str]] = {}
    point_cost: dict[str, Any] = {}
    for p in points:
        pid = p["id"]
        holds = set(p.get("hold_events", []))
        effective_blocked[pid] = index.descendant_closure(holds)
        point_cost[pid] = p.get("downtime_minutes", 0)

    best: dict[str, Any] | None = None
    evaluated = 0
    total_masks = 1 << n

    for mask in range(total_masks):
        selected = _mask_ids(points, mask)
        cost = sum(point_cost[pid] for pid in selected)
        if best is not None and cost > best["total_downtime_minutes"]:
            continue
        evaluated += 1

        blocked: set[str] = set()
        for pid in selected:
            blocked |= effective_blocked[pid]

        reasons: list[str] = []
        feasible = True

        # Uncertain candidates must have no reachable passing prefix after the
        # pause/hold set is applied.
        for cid in uncertain:
            if has_any_pass(index, index.candidate_by_id[cid], blocked, cache):
                feasible = False
                reasons.append(f"uncertain candidate {cid} can still reach a passing prefix")
                break
        if feasible:
            for cid in mandatory:
                mandatory_report = certify_candidate(index, cid, blocked, cache)
                # A mandatory compliance artifact must remain certifiable under
                # every residual legal order, not merely have one lucky order.
                if mandatory_report["verdict"] != "always_releasable":
                    feasible = False
                    reasons.append(f"mandatory candidate {cid} is no longer universally releasable")
                    break

        if not feasible:
            continue

        key = (cost, tuple(sorted(selected)))
        if best is None or key < best["_key"]:
            candidate_results = {}
            for cid in uncertain + mandatory:
                r = certify_candidate(index, cid, blocked, cache)
                candidate_results[cid] = {
                    "verdict": r["verdict"],
                    "certify": r["certify"],
                    "pass_exists": r["pass_exists"],
                }
            best = {
                "_key": key,
                "selected_pause_point_ids": sorted(selected),
                "total_downtime_minutes": cost,
                "effective_blocked_event_ids": sorted(blocked),
                "candidate_results": candidate_results,
                "feasibility_reasons": [
                    "every order-dependent candidate has pass_exists=false",
                    "every mandatory candidate remains always_releasable",
                ],
            }

    if best is None:
        return {
            "schema": "splitrelease.protect-plan/v1",
            "case_id": index.raw.get("case_id", "unnamed-case"),
            "feasible": False,
            "pause_point_count": n,
            "subsets_enumerated": total_masks,
            "subsets_evaluated_after_cost_pruning": evaluated,
            "uncertain_candidate_ids": uncertain,
            "mandatory_candidate_ids": mandatory,
            "error": "no pause subset blocks every uncertain pass while preserving all mandatory candidates",
        }

    best.pop("_key", None)
    selected_set = set(best["selected_pause_point_ids"])
    best["selected_pause_points"] = [
        {
            "id": p["id"],
            "downtime_minutes": p.get("downtime_minutes", 0),
            "hold_events": p.get("hold_events", []),
            "effective_blocked_event_ids": sorted(effective_blocked[p["id"]]),
            "note": p.get("note"),
        }
        for p in points
        if p["id"] in selected_set
    ]
    return {
        "schema": "splitrelease.protect-plan/v1",
        "case_id": index.raw.get("case_id", "unnamed-case"),
        "feasible": True,
        "optimization": "minimum sum of downtime_minutes over all 2^N subsets; ties by lexicographic selected IDs",
        "pause_point_count": n,
        "subsets_enumerated": total_masks,
        "subsets_evaluated_after_cost_pruning": evaluated,
        "uncertain_candidate_ids": uncertain,
        "mandatory_candidate_ids": mandatory,
        **best,
    }
