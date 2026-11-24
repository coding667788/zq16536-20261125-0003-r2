import copy
import json
import tempfile
import unittest
from pathlib import Path

from splitrelease.caseio import CaseIndex, legal_topological_orders
from splitrelease.engine import prepare_analysis, replay_order
from splitrelease.fixtures import sample_case
from splitrelease.service import certify_case


class TopologyOracleTest(unittest.TestCase):
    def setUp(self):
        self.raw = sample_case()
        self.index = CaseIndex(copy.deepcopy(self.raw))
        self.candidate = self.index.candidate_by_id["rc-combo"]
        self.prepared = prepare_analysis(self.index, self.candidate)
        self.win = self.prepared["window_ids"]

    def test_all_legal_orders_match_engine_verdict(self):
        orders = legal_topological_orders(self.win, self.index.preds)
        # Two revoke->restore chains over six events: 6! / (2*2) = 180.
        self.assertEqual(180, len(orders))

        oracle_pass = 0
        oracle_fail = 0
        for order in orders:
            _, _, tally = replay_order(
                self.index,
                order,
                self.prepared["specs"],
                self.prepared["threshold"],
                self.prepared["required_groups"],
                self.prepared["base_state"],
            )
            if tally["passed"]:
                oracle_pass += 1
            else:
                oracle_fail += 1

        report = certify_case(self.index, include_evidence=False)
        combo = next(c for c in report["candidates"] if c["candidate_id"] == "rc-combo")
        self.assertEqual("order_dependent", combo["verdict"])
        self.assertTrue(combo["pass_exists"])
        self.assertIsNotNone(combo["reject_witness"])
        self.assertGreater(oracle_pass, 0)
        self.assertGreater(oracle_fail, 0)

    def order_tally(self, order):
        legal = legal_topological_orders(self.win, self.index.preds)
        self.assertIn(order, legal)
        _, _, tally = replay_order(
            self.index,
            order,
            self.prepared["specs"],
            self.prepared["threshold"],
            self.prepared["required_groups"],
            self.prepared["base_state"],
        )
        return tally

    def test_each_revocation_reversal_alone_passes(self):
        only_a_bad = [
            "vote-dave",
            "revoke-carol",
            "vote-carol",
            "restore-carol",
            "revoke-dave",
            "restore-dave",
        ]
        tally = self.order_tally(only_a_bad)
        self.assertTrue(tally["passed"], tally)
        self.assertEqual(3, tally["effective_vote_count"])
        self.assertNotIn("p-carol", tally["distinct_natural_person_ids"])
        self.assertIn("p-dave", tally["distinct_natural_person_ids"])

        only_b_bad = [
            "vote-carol",
            "revoke-dave",
            "vote-dave",
            "restore-dave",
            "revoke-carol",
            "restore-carol",
        ]
        tally = self.order_tally(only_b_bad)
        self.assertTrue(tally["passed"], tally)
        self.assertEqual(3, tally["effective_vote_count"])

    def test_two_independent_adverse_revocations_combine_to_failure(self):
        both_bad = [
            "revoke-carol",
            "revoke-dave",
            "vote-carol",
            "restore-carol",
            "vote-dave",
            "restore-dave",
        ]
        tally = self.order_tally(both_bad)
        self.assertFalse(tally["passed"])
        self.assertEqual(2, tally["effective_vote_count"])
        self.assertEqual({"p-alice", "p-bob"}, set(tally["distinct_natural_person_ids"]))

    def test_reversing_file_arrays_does_not_change_result(self):
        reversed_raw = copy.deepcopy(self.raw)
        for log in reversed_raw["logs"].values():
            log.reverse()
        for key in ("build_prefix", "approval_prefix"):
            reversed_raw["checkpoint"][key].reverse()

        idx_a = CaseIndex(copy.deepcopy(self.raw))
        idx_b = CaseIndex(reversed_raw)
        rep_a = certify_case(idx_a, include_evidence=True)
        rep_b = certify_case(idx_b, include_evidence=True)
        self.assertEqual(
            json.dumps(rep_a, ensure_ascii=False, sort_keys=True),
            json.dumps(rep_b, ensure_ascii=False, sort_keys=True),
        )

    def test_shuffled_utf8_json_file_is_not_used_as_causality(self):
        shuffled = copy.deepcopy(self.raw)
        for log in shuffled["logs"].values():
            # Deterministic permutation; physical order is deliberately strange.
            log.sort(key=lambda e: e["id"], reverse=True)
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "shuffled.json"
            path.write_text(json.dumps(shuffled, ensure_ascii=False), encoding="utf-8")
            from splitrelease.caseio import load_case

            idx = load_case(path)
            report = certify_case(idx, include_evidence=False)
        combo = next(c for c in report["candidates"] if c["candidate_id"] == "rc-combo")
        self.assertEqual("order_dependent", combo["verdict"])


if __name__ == "__main__":
    unittest.main()
