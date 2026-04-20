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
    from artifact_locator import ArtifactLocator

    path = ArtifactLocator(Path(".")).latest_threats()
    if path is None:
        raise FileNotFoundError(
            "No threat artifacts found in models/outputs/threats/. "
            "Run 'threatforge generate-threats' first or pass --threats."
        )
    return path


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


def _cmd_sync(args: argparse.Namespace) -> int:
    from knowledge.sync import sync, sync_status

    if args.status:
        info = sync_status()
        for key, value in info.items():
            print(f"  {key}: {value}")
        return 0

    try:
        counts = sync(
            attack_version=args.attack_version,
            atlas_version=args.atlas_version,
            offline_dir=args.offline,
            embed=args.embed,
            neo4j=args.neo4j,
            map_heuristics=args.map_heuristics,
            map_threshold=args.map_threshold,
            map_top_k=args.map_top_k,
            map_output=args.map_output,
        )
    except Exception as exc:
        print(f"FAILED: {exc}")
        return 1

    print("SYNC COMPLETE")
    print(f"  tactics:     {counts['tactics']}")
    print(f"  techniques:  {counts['techniques']}")
    print(f"  mitigations: {counts['mitigations']}")
    if "neo4j_techniques" in counts:
        print(f"  neo4j:")
        print(f"    techniques:  {counts['neo4j_techniques']}")
        print(f"    tactics:     {counts['neo4j_tactics']}")
        print(f"    mitigations: {counts['neo4j_mitigations']}")
        print(f"    rules:       {counts['neo4j_heuristic_rules']}")
        print(f"    maps_to:     {counts['neo4j_maps_to']}")
        print(f"    ctrl_bridges:{counts['neo4j_implements_control']}")
    if "embedded" in counts:
        print(f"  embedded:    {counts['embedded']}")
    if "suggestions" in counts:
        print(f"  suggestions: {counts['suggestions']}")
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


def _cmd_suggest_mappings(args: argparse.Namespace) -> int:
    from analysis.heuristics import discovered_heuristics
    from analysis.mapping_loader import load_curated_mappings
    from analysis.suggestion_scorer import ScoredSuggestion, score_suggestions
    from knowledge.index import TechniqueIndex
    from knowledge.store import TechniqueStore
    from knowledge.vector_index import VectorIndex

    try:
        from knowledge.embedder import SentenceTransformerEmbedder
    except ImportError:
        print("sentence-transformers is required. Install with: pip install -e '.[suggest]'")
        return 1

    store = TechniqueStore()
    embedder = SentenceTransformerEmbedder()
    vec_idx = VectorIndex(store, embedder.model_name)

    if not vec_idx.is_populated:
        print("No embeddings found. Run 'threatforge sync --embed' first.")
        store.close()
        return 1

    tech_idx = TechniqueIndex(store)

    if args.rule_id:
        heuristics = discovered_heuristics()
        heuristic = next(
            (h for h in heuristics if h.rule_id == args.rule_id), None,
        )
        if not heuristic:
            print(f"Unknown rule_id: {args.rule_id}")
            store.close()
            return 1
        query_text = f"{heuristic.name}. {heuristic.description}"
        curated = load_curated_mappings(args.rule_id, index=tech_idx)
        target_frameworks = heuristic.frameworks
    else:
        query_text = args.description
        curated = ()
        target_frameworks = ()

    suggestions = score_suggestions(
        rule_id=args.rule_id or "AD-HOC",
        heuristic_text=query_text,
        embedder=embedder,
        vector_index=vec_idx,
        technique_index=tech_idx,
        curated_mappings=curated,
        target_frameworks=target_frameworks,
        top_k=args.top_k,
    )
    suggestions = [s for s in suggestions if s.composite_score >= args.threshold]
    store.close()

    if not suggestions:
        print("No suggestions above threshold.")
        return 0

    if args.format == "json":
        import json

        print(json.dumps(
            [{
                "technique_id": s.technique_id,
                "technique_name": s.technique_name,
                "framework": s.framework,
                "tactic": s.tactic,
                "composite_score": round(s.composite_score, 4),
                "vector_score": round(s.vector_score, 4),
                "explanation": s.explanation,
            } for s in suggestions],
            indent=2,
        ))
    elif args.format == "toml":
        for s in suggestions:
            print(f'[[mappings]]')
            print(f'rule_id = "{args.rule_id or "AD-HOC"}"')
            print(f'technique_id = "{s.technique_id}"')
            print(f'framework = "{s.framework}"')
            print(f'tactic = "{s.tactic}"')
            print(f'rationale = "{s.explanation}"')
            print()
    else:
        header = f"{'Rank':<5} {'ID':<14} {'Name':<40} {'Tactic':<25} {'Score':>6}"
        print(header)
        print("-" * len(header))
        for rank, s in enumerate(suggestions, 1):
            name = s.technique_name[:38]
            print(
                f"{rank:<5} {s.technique_id:<14} {name:<40} "
                f"{s.tactic:<25} {s.composite_score:>6.3f}"
            )

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

    # sync
    p_sync = sub.add_parser("sync", help="Sync MITRE ATT&CK and ATLAS knowledge base")
    p_sync.add_argument("--attack-version", default="latest", help="ATT&CK version to fetch (default: latest)")
    p_sync.add_argument("--atlas-version", default="latest", help="ATLAS version to fetch (default: latest)")
    p_sync.add_argument("--offline", type=Path, default=None, help="Directory with local STIX/ATLAS files")
    p_sync.add_argument("--status", action="store_true", help="Show current sync status")
    p_sync.add_argument("--embed", action="store_true", help="Generate technique embeddings after sync")
    p_sync.add_argument("--neo4j", action="store_true", help="Load MITRE knowledge graph into Neo4j")
    p_sync.add_argument("--map-heuristics", action="store_true", help="Generate suggested technique mappings for all heuristics")
    p_sync.add_argument("--map-threshold", type=float, default=0.40, help="Min composite score for suggestions (default: 0.40)")
    p_sync.add_argument("--map-top-k", type=int, default=10, help="Max suggestions per heuristic (default: 10)")
    p_sync.add_argument("--map-output", type=Path, default=None, help="Output path for suggestions TOML")

    # suggest-mappings
    p_sg = sub.add_parser("suggest-mappings", help="Suggest technique mappings for a heuristic using vector similarity")
    p_sg_group = p_sg.add_mutually_exclusive_group(required=True)
    p_sg_group.add_argument("--rule-id", type=str, help="Heuristic rule ID (e.g. TH-007)")
    p_sg_group.add_argument("--description", type=str, help="Freeform heuristic description")
    p_sg.add_argument("--top-k", type=int, default=15, help="Max suggestions (default: 15)")
    p_sg.add_argument("--threshold", type=float, default=0.30, help="Min composite score (default: 0.30)")
    p_sg.add_argument("--format", choices=["table", "json", "toml"], default="table", help="Output format")

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
        "sync": _cmd_sync,
        "suggest-mappings": _cmd_suggest_mappings,
    }
    return dispatch[args.command](args)


def entry_point() -> None:
    raise SystemExit(main())
