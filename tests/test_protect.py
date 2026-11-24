import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from splitrelease.caseio import CaseIndex
from splitrelease.fixtures import sample_case
from splitrelease.service import plan_protection


class ProtectTest(unittest.TestCase):
    def setUp(self):
        self.raw = sample_case()
        self.index = CaseIndex(copy.deepcopy(self.raw))
        self.plan = plan_protection(self.index)

    def test_sixteen_pause_points_and_minimum_plan(self):
        self.assertEqual(16, len(self.raw["pause_points"]))
        self.assertEqual(16, self.plan["pause_point_count"])
        self.assertEqual(1 << 16, self.plan["subsets_enumerated"])
        self.assertTrue(self.plan["feasible"])
        self.assertEqual(7, self.plan["total_downtime_minutes"])
        self.assertEqual(["pp16-contested-bundle"], self.plan["selected_pause_point_ids"])

    def test_uncertain_candidates_blocked_and_mandatory_preserved(self):
        results = self.plan["candidate_results"]
        self.assertEqual("never_releasable", results["rc-combo"]["verdict"])
        self.assertFalse(results["rc-combo"]["pass_exists"])
        self.assertEqual("never_releasable", results["rc-alias"]["verdict"])
        self.assertFalse(results["rc-alias"]["pass_exists"])
        self.assertEqual("always_releasable", results["rc-safe"]["verdict"])
        self.assertTrue(results["rc-safe"]["pass_exists"])
        self.assertIn("rc-safe", self.raw and [c["id"] for c in self.raw["candidates"] if c.get("mandatory")])

    def test_cheap_global_gate_is_infeasible_because_mandatory(self):
        # pp12 costs one minute but withholds mandatory safe votes too.
        pp12 = next(p for p in self.raw["pause_points"] if p["id"] == "pp12-global-vote-gate")
        self.assertEqual(1, pp12["downtime_minutes"])
        self.assertIn("sv1", pp12["hold_events"])

    def test_cli_protect_outputs_utf8_json(self):
        with tempfile.TemporaryDirectory() as td:
            case_path = Path(td) / "case.json"
            out_path = Path(td) / "protect.json"
            case_path.write_text(json.dumps(self.raw, ensure_ascii=False), encoding="utf-8")
            root = Path(__file__).resolve().parents[1]
            proc = subprocess.run(
                [sys.executable, "-I", "run_splitrelease.py", "protect", str(case_path), "--out", str(out_path)],
                cwd=root,
                text=True,
                capture_output=True,
                encoding="utf-8",
                check=False,
            )
            self.assertEqual(0, proc.returncode, proc.stderr)
            data = json.loads(out_path.read_text(encoding="utf-8"))
            self.assertTrue(data["feasible"])
            self.assertEqual(["pp16-contested-bundle"], data["selected_pause_point_ids"])


if __name__ == "__main__":
    unittest.main()
