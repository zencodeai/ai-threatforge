from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from analysis.threat_outputs import generate_threat_report


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate structured threat outputs from graph evidence"
    )
    parser.add_argument(
        "--model",
        required=True,
        type=Path,
        help="Path to canonical TOML model",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Optional output file path for generated threats JSON",
    )
    args = parser.parse_args()

    try:
        report, path = generate_threat_report(args.model, args.output)
    except Exception as exc:  # pragma: no cover - CLI pass-through
        print(f"FAILED: {exc}")
        return 1

    print(f"GENERATED: {report.threat_count} threats")
    print(f"OUTPUT: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
