from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from graph.graph_loader import load_model_into_graph


def main() -> int:
    parser = argparse.ArgumentParser(description="Load canonical TOML model into Neo4j")
    parser.add_argument(
        "--model",
        required=True,
        type=Path,
        help="Path to canonical TOML model",
    )
    parser.add_argument(
        "--clear",
        action="store_true",
        help="Clear all existing graph data before loading model",
    )
    args = parser.parse_args()

    try:
        stats = load_model_into_graph(args.model, clear_graph=args.clear)
    except Exception as exc:  # pragma: no cover - CLI pass-through
        print(f"FAILED: {exc}")
        return 1

    print(
        f"LOADED: nodes={stats.nodes_created} relationships={stats.relationships_created}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
