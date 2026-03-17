from __future__ import annotations

import argparse
from pathlib import Path

from models.schema.canonical_model import validate_canonical_model


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate canonical ThreatGraph TOML model")
    parser.add_argument(
        "--model",
        required=True,
        type=Path,
        help="Path to TOML model file",
    )
    args = parser.parse_args()

    ok, message = validate_canonical_model(args.model)
    if ok:
        print(f"VALID: {args.model}")
        return 0

    print(f"INVALID: {args.model}")
    print(message)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
