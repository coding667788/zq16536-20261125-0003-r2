import time
import unittest

from splitrelease.caseio import CaseIndex
from splitrelease.fixtures import large_case
from splitrelease.service import certify_case, plan_protection


class HundredThousandLogPerformanceTest(unittest.TestCase):
    def test_100k_ordinary_events_and_small_ambiguous_window(self):
        raw = large_case(100_000)
        total = len(raw["logs"]["build_log"]) + len(raw["logs"]["approval_log"])
        self.assertEqual(100_000, total)
        for window in raw["windows"]:
            self.assertLessEqual(len(window["event_ids"]), 16)

        start = time.perf_counter()
        index = CaseIndex(raw)
        report = certify_case(index, include_evidence=False)
        certify_elapsed = time.perf_counter() - start

        self.assertEqual(2, report["summary"]["order_dependent"])
        self.assertEqual(1, report["summary"]["always_releasable"])
        self.assertEqual(1, report["summary"]["never_releasable"])
        # Generous for an ordinary Windows CPU; observed far below this.
        self.assertLess(certify_elapsed, 20.0, f"certify took {certify_elapsed:.2f}s")

        start = time.perf_counter()
        plan = plan_protection(index)
        protect_elapsed = time.perf_counter() - start
        self.assertTrue(plan["feasible"])
        self.assertEqual(["pp16-contested-bundle"], plan["selected_pause_point_ids"])
        self.assertLess(protect_elapsed, 30.0, f"protect took {protect_elapsed:.2f}s")


if __name__ == "__main__":
    unittest.main()
