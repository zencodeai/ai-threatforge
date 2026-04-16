from __future__ import annotations

import argparse
import sys
from pathlib import Path


def _cmd_validate(args: argparse.Namespace) -> int:
    from models.schema.canonical_model import validate_canonical_model

    ok, message = validate_canonical_model(args.model)
    if ok:
        print(f"VALID: {args.model}")
        return 0
    print(f"INVALID: {args.model}")
    print(message)
    return 1


def _cmd_load_graph(args: argparse.Namespace) -> int:
    from graph.graph_loader import load_model_into_graph

    try:
        stats = load_model_into_graph(args.model, clear_graph=args.clear)
    except Exception as exc:
        print(f"FAILED: {exc}")
        return 1
    print(f"LOADED: nodes={stats.nodes_created} relationships={stats.relationships_created}")
    return 0


def _cmd_generate_threats(args: argparse.Namespace) -> int:
    from analysis.threat_outputs import generate_threat_report

    try:
        report, path = generate_threat_report(args.model, args.output)
    except Exception as exc:
        print(f"FAILED: {exc}")
        return 1
    print(f"GENERATED: {report.threat_count} threats")
    print(f"OUTPUT: {path}")
    return 0


def _default_threat_path() -> Path:
    candidates = sorted(Path("models/outputs/threats").glob("*_threats.json"))
    if not candidates:
        raise FileNotFoundError(
            "No threat artifacts found in models/outputs/threats/. "
            "Run 'threatforge generate-threats' first or pass --threats."
        )
    return candidates[-1]


def _cmd_score_risks(args: argparse.Namespace) -> int:
    from analysis.risk_scoring import generate_risk_report_from_file

    try:
        threat_path = args.threats or _default_threat_path()
        report, output_path = generate_risk_report_from_file(threat_path, args.output)
    except Exception as exc:
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


def _cmd_ui(args: argparse.Namespace) -> int:
    try:
        import streamlit.web.cli as stcli
    except ImportError:
        print("Streamlit is not installed. Install with: pip install -e '.[ui]'")
        return 1

    app_path = str(Path(__file__).resolve().parent.parent / "ui" / "app.py")
    sys.argv = ["streamlit", "run", app_path, "--server.headless=true"]
    stcli.main()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="threatforge",
        description="Threat Forge AI — model-driven threat modeling platform",
    )
    sub = parser.add_subparsers(dest="command")

    # validate
    p_val = sub.add_parser("validate", help="Validate a canonical TOML model")
    p_val.add_argument("--model", required=True, type=Path, help="Path to TOML model file")

    # load-graph
    p_lg = sub.add_parser("load-graph", help="Load canonical model into Neo4j")
    p_lg.add_argument("--model", required=True, type=Path, help="Path to canonical TOML model")
    p_lg.add_argument("--clear", action="store_true", help="Clear existing graph data first")

    # generate-threats
    p_gt = sub.add_parser("generate-threats", help="Generate structured threat outputs")
    p_gt.add_argument("--model", required=True, type=Path, help="Path to canonical TOML model")
    p_gt.add_argument("--output", type=Path, default=None, help="Output file path for threats JSON")

    # score-risks
    p_sr = sub.add_parser("score-risks", help="Score threats into prioritized risk records")
    p_sr.add_argument("--threats", type=Path, default=None, help="Path to threat report JSON")
    p_sr.add_argument("--output", type=Path, default=None, help="Output path for risk report JSON")

    # ui
    sub.add_parser("ui", help="Launch the Streamlit analyst interface")

    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 0

    dispatch = {
        "validate": _cmd_validate,
        "load-graph": _cmd_load_graph,
        "generate-threats": _cmd_generate_threats,
        "score-risks": _cmd_score_risks,
        "ui": _cmd_ui,
    }
    return dispatch[args.command](args)


def entry_point() -> None:
    raise SystemExit(main())
