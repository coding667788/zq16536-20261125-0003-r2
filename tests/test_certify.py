import copy
import unittest

from splitrelease.caseio import CaseIndex
from splitrelease.fixtures import sample_case
from splitrelease.service import certify_case


class CertifyTest(unittest.TestCase):
    def setUp(self):
        self.raw = sample_case()
        self.index = CaseIndex(copy.deepcopy(self.raw))
        self.report = certify_case(self.index, include_evidence=False)
        self.by_id = {c["candidate_id"]: c for c in self.report["candidates"]}

    def test_three_way_verdicts(self):
        self.assertEqual("order_dependent", self.by_id["rc-combo"]["verdict"])
        self.assertEqual("CASE", self.by_id["rc-combo"]["certify"])
        self.assertEqual("order_dependent", self.by_id["rc-alias"]["verdict"])
        self.assertEqual("always_releasable", self.by_id["rc-safe"]["verdict"])
        self.assertEqual("YES", self.by_id["rc-safe"]["certify"])
        self.assertEqual("never_releasable", self.by_id["rc-denied"]["verdict"])
        self.assertEqual("NO", self.by_id["rc-denied"]["certify"])

    def test_case_has_pass_and_reject_review_prefixes(self):
        combo = self.by_id["rc-combo"]
        self.assertTrue(combo["pass_witness"]["complete_review_prefix"])
        self.assertTrue(combo["reject_witness"]["complete_review_prefix"])
        self.assertTrue(combo["pass_witness"]["tally"]["passed"])
        self.assertFalse(combo["reject_witness"]["tally"]["passed"])
        self.assertTrue(combo["reject_witness"]["terminal_full_window"])

        alias = self.by_id["rc-alias"]
        self.assertTrue(alias["pass_witness"]["tally"]["passed"])
        self.assertFalse(alias["reject_witness"]["tally"]["passed"])
        self.assertEqual(["vote-roving"], alias["pass_witness"]["post_checkpoint_order"])
        self.assertEqual(["alias-move-mallory", "vote-roving"], alias["reject_witness"]["post_checkpoint_order"])

    def test_same_group_name_is_not_identity(self):
        tally = self.by_id["rc-combo"]["pass_witness"]["tally"]
        # The two release groups share group_name but have distinct IDs/keys.
        self.assertEqual({"grp-release-a", "grp-release-b"}, set(tally["group_ids"]))
        self.assertEqual({"ind-release-a", "ind-release-b"}, set(tally["independence_keys"]))

    def test_mutable_tag_move_does_not_replace_digest_pinned_object(self):
        tag_events = [e for e in self.raw["logs"]["build_log"] if e["kind"] == "tag_move"]
        self.assertEqual("tag-move-release", tag_events[0]["id"])
        safe = self.by_id["rc-safe"]
        self.assertEqual("sha256:safe-v1", safe["artifact_digest"])
        self.assertEqual("always_releasable", safe["verdict"])

    def test_natural_person_alias_duplicates_count_once(self):
        raw = copy.deepcopy(self.raw)
        # Add a second alias for p-safe1 and a duplicate receipt.  It must not
        # create a fourth natural person or change the minimum certificate.
        raw["logs"]["approval_log"].append(
            {"id": "safe1-other-alias", "kind": "alias_binding", "auth_ref": "safe1-backup-key", "person_id": "p-safe1"}
        )
        raw["checkpoint"]["approval_prefix"].append("safe1-other-alias")
        raw["logs"]["approval_log"].append(
            {
                "id": "sv1-duplicate",
                "kind": "vote",
                "phase": "ga",
                "auth_ref": "safe1-backup-key",
                "closure_digest": next(
                    c for c in self.raw["logs"]["approval_log"] if c["id"] == "sv1"
                )["closure_digest"],
                "group_id": "grp-safe-a",
                "independence_key": "ind-safe-a",
            }
        )
        raw["checkpoint"]["approval_prefix"].append("sv1-duplicate")
        idx = CaseIndex(raw)
        report = certify_case(idx, include_evidence=False)
        safe = next(c for c in report["candidates"] if c["candidate_id"] == "rc-safe")
        self.assertEqual("always_releasable", safe["verdict"])
        self.assertEqual(3, safe["pass_witness"]["tally"]["threshold"])


if __name__ == "__main__":
    unittest.main()
