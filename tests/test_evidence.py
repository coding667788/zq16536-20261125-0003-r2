import copy
import unittest

from splitrelease.caseio import CaseIndex
from splitrelease.evidence import find_minimal_evidence
from splitrelease.fixtures import sample_case
from splitrelease.service import certify_case


class EvidenceTest(unittest.TestCase):
    def test_minimal_evidence_count_and_id_tie_break(self):
        index = CaseIndex(copy.deepcopy(sample_case()))
        report = certify_case(index, include_evidence=True)
        safe = next(c for c in report["candidates"] if c["candidate_id"] == "rc-safe")
        evidence = safe["minimal_evidence"]
        self.assertEqual(5, evidence["minimal_event_count"])
        self.assertEqual(
            ["build-core-v1", "build-safe-v1", "sv1", "sv2", "sv3"],
            evidence["event_ids"],
        )
        self.assertEqual(["sv1", "sv2", "sv3"], evidence["selected_vote_ids"])
        self.assertEqual("always_releasable", evidence["universal_replay"]["verdict"])

    def test_causal_predecessors_are_retained_and_counted(self):
        raw = copy.deepcopy(sample_case())
        # Force sv3 into the only threshold-meeting subset by removing the
        # redundant fourth vote and pause points that name it.
        raw["pause_points"] = []
        raw["logs"]["approval_log"] = [e for e in raw["logs"]["approval_log"] if e["id"] != "sv4"]
        raw["checkpoint"]["approval_prefix"] = [x for x in raw["checkpoint"]["approval_prefix"] if x != "sv4"]
        raw["logs"]["approval_log"].append(
            {"id": "prov-sv3", "kind": "signing_provenance", "signer": "notary-3"}
        )
        for event in raw["logs"]["approval_log"]:
            if event["id"] == "sv3":
                event["predecessors"] = ["prov-sv3"]
        raw["checkpoint"]["approval_prefix"].append("prov-sv3")

        index = CaseIndex(raw)
        report = certify_case(index, include_evidence=True)
        safe = next(c for c in report["candidates"] if c["candidate_id"] == "rc-safe")
        evidence = safe["minimal_evidence"]
        self.assertEqual(6, evidence["minimal_event_count"])
        self.assertIn("prov-sv3", evidence["event_ids"])
        self.assertIn("prov-sv3", evidence["causal_predecessor_ids_retained"])

    def test_evidence_function_returns_none_for_non_safe(self):
        index = CaseIndex(copy.deepcopy(sample_case()))
        report = certify_case(index, include_evidence=False)
        combo = next(c for c in report["candidates"] if c["candidate_id"] == "rc-combo")
        self.assertIsNone(find_minimal_evidence(index, index.candidate_by_id["rc-combo"], combo))


if __name__ == "__main__":
    unittest.main()
