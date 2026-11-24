"""Command-line interface: all input and output is UTF-8 JSON."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .caseio import CaseError, load_case
from .fixtures import write_fixture
from .service import certify_case, plan_protection


def _dump_json(obj: Any, out: str | None = None) -> int:
    text = json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=False)
    if out:
        path = Path(out)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text + "\n", encoding="utf-8")
    else:
        sys.stdout.write(text + "\n")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="splitrelease",
        description="Certify split immutable logs and optimize protective pause points.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_cert = sub.add_parser("certify", help="classify every release candidate as YES/NO/CASE")
    p_cert.add_argument("case", help="path to UTF-8 JSON case file")
    p_cert.add_argument("--candidate", help="optional candidate id filter")
    p_cert.add_argument("--no-evidence", action="store_true", help="skip minimum evidence computation")
    p_cert.add_argument("--out", help="write JSON report here instead of stdout")

    p_prot = sub.add_parser("protect", help="choose minimum-downtime pause subset")
    p_prot.add_argument("case", help="path to UTF-8 JSON case file")
    p_prot.add_argument("--out", help="write JSON plan here instead of stdout")

    p_fix = sub.add_parser("fixture", help="write an offline synthetic JSON fixture")
    p_fix.add_argument("kind", choices=("sample", "topo-small", "large"))
    p_fix.add_argument("--out", required=True)

    return parser


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8")
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "fixture":
            path = write_fixture(args.kind, args.out)
            return _dump_json({"wrote": str(path), "kind": args.kind})

        index = load_case(args.case)
        if args.command == "certify":
            report = certify_case(index, include_evidence=not args.no_evidence)
            if args.candidate:
                report["candidates"] = [c for c in report["candidates"] if c["candidate_id"] == args.candidate]
                if not report["candidates"]:
                    raise CaseError(f"unknown candidate {args.candidate!r}")
                report["summary"]["candidate_count"] = len(report["candidates"])
            return _dump_json(report, args.out)

        if args.command == "protect":
            return _dump_json(plan_protection(index), args.out)

        parser.error(f"unknown command {args.command}")
        return 2
    except (CaseError, ValueError, KeyError) as exc:
        error = {"schema": "splitrelease.error/v1", "error": type(exc).__name__, "message": str(exc)}
        sys.stderr.write(json.dumps(error, ensure_ascii=False, indent=2) + "\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
