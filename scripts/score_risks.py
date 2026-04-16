from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from analysis.risk_scoring import generate_risk_report_from_file


def _default_threat_path() -> Path:
    candidates = sorted(Path("models/outputs/threats").glob("*_threats.json"))
    if not candidates:
        raise FileNotFoundError(
            "No threat artifacts found in models/outputs/threats/. "
            "Run scripts/generate_threats.py first or pass --threats."
        )
    return candidates[-1]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Score threats into prioritized risk records"
    )
    parser.add_argument(
        "--threats",
        type=Path,
        default=None,
        help="Path to threat report JSON (defaults to latest models/outputs/threats/*_threats.json)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Optional output path for risk report JSON",
    )
    args = parser.parse_args()

    try:
        threat_path = args.threats or _default_threat_path()
        report, output_path = generate_risk_report_from_file(threat_path, args.output)
    except Exception as exc:  # pragma: no cover - CLI passthrough
        print(f"FAILED: {exc}")
        return 1

    priority_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for risk in report.risks:
        priority_counts[risk.priority] += 1

    print(f"THREATS INPUT: {threat_path}")
    print(f"GENERATED: {report.risk_count} risks")
    print("PRIORITIES:")
    print(f"  critical: {priority_counts['critical']}")
    print(f"  high: {priority_counts['high']}")
    print(f"  medium: {priority_counts['medium']}")
    print(f"  low: {priority_counts['low']}")
    print("TOP RISKS:")

    for risk in report.risks[:5]:
        top_driver = risk.drivers[0].factor if risk.drivers else "n/a"
        print(
            f"  {risk.risk_id} | score={risk.risk_score:.2f} | "
            f"priority={risk.priority} | target={risk.target_id} | driver={top_driver}"
        )

    print(f"OUTPUT: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
