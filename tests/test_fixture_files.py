import unittest
from pathlib import Path

from splitrelease.caseio import load_case
from splitrelease.service import certify_case, plan_protection

ROOT = Path(__file__).resolve().parents[1]


class OnDiskFixtureTest(unittest.TestCase):
    def test_sample_json_fixture_loads_and_certifies(self):
        index = load_case(ROOT / "fixtures" / "sample_case.json")
        report = certify_case(index, include_evidence=True)
        self.assertEqual(
            {"always_releasable": 1, "order_dependent": 2, "never_releasable": 1},
            {k: report["summary"][k] for k in ("always_releasable", "order_dependent", "never_releasable")},
        )
        plan = plan_protection(index)
        self.assertEqual(["pp16-contested-bundle"], plan["selected_pause_point_ids"])

    def test_topo_small_fixture_loads(self):
        index = load_case(ROOT / "fixtures" / "topo_small_case.json")
        self.assertEqual(1, len(index.candidates))
        self.assertEqual(6, len(index.windows["w-two-revocations"]["event_ids"]))


if __name__ == "__main__":
    unittest.main()
