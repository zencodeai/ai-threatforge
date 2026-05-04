from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from app import AnalysisService, KnowledgeService
from project_paths import ProjectPaths
from session_store import SessionStore
from toml_utils import toml_string


def _graphrag_enabled(args: argparse.Namespace) -> bool:
    """Resolve whether GraphRAG mode is active.

    Priority: ``--graphrag`` flag (force on) > ``THREATFORGE_GRAPHRAG``
    env var (``1`` = on).
    """
    if getattr(args, "graphrag", False) or getattr(args, "enrich", False):
        return True
    return os.environ.get("THREATFORGE_GRAPHRAG", "") == "1"


def _session_store() -> SessionStore:
    return SessionStore(ProjectPaths.default())


def _analysis_service() -> AnalysisService:
    store = _session_store()
    return AnalysisService(paths=store.paths, session_store=store)


def _knowledge_service() -> KnowledgeService:
    return KnowledgeService(paths=ProjectPaths.default())


def _cmd_validate(args: argparse.Namespace) -> int:
    result = _analysis_service().validate_model(args.model)
    if result.stdout:
        print(result.stdout)
    if result.stderr:
        print(result.stderr, file=sys.stderr)
    return result.returncode


def _cmd_load_graph(args: argparse.Namespace) -> int:
    result = _analysis_service().load_graph(args.model, clear_graph=args.clear)
    if result.stdout:
        print(result.stdout)
    if result.stderr:
        print(result.stderr, file=sys.stderr)
    return result.returncode


def _cmd_generate_threats(args: argparse.Namespace) -> int:
    result = _analysis_service().generate_threats(
        args.model,
        output_path=args.output,
        enrich=_graphrag_enabled(args),
    )
    if result.stdout:
        print(result.stdout)
    if result.stderr:
        print(result.stderr, file=sys.stderr)
    return result.returncode


def _cmd_score_risks(args: argparse.Namespace) -> int:
    result = _analysis_service().score_risks(
        threat_path=args.threats,
        output_path=args.output,
    )
    if result.stdout:
        print(result.stdout)
    if result.stderr:
        print(result.stderr, file=sys.stderr)
    return result.returncode


def _cmd_session(args: argparse.Namespace) -> int:
    store = _session_store()

    if args.clear:
        store.clear()
        print("CLEARED: default session")
        return 0

    if args.model is not None:
        _analysis_service().record_model_session(args.model)

    state = store.load()
    print(json.dumps({
        "session_id": state.session_id,
        "model_path": state.model_path,
        "model_id": state.model_id,
        "manifest_path": state.manifest_path,
        "threat_report_path": state.threat_report_path,
        "risk_report_path": state.risk_report_path,
        "last_updated": state.last_updated,
    }, indent=2))
    return 0


def _cmd_sync(args: argparse.Namespace) -> int:
    if args.status:
        info = _knowledge_service().status()
        for key, value in info.items():
            print(f"  {key}: {value}")
        return 0

    result = _knowledge_service().sync(
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
    if result.stdout:
        print(result.stdout)
    if result.stderr:
        print(result.stderr, file=sys.stderr)
    return result.returncode


def _cmd_ui(args: argparse.Namespace) -> int:
    try:
        import streamlit.web.cli as stcli
    except ImportError:
        print("Streamlit is not installed. Install with: pip install -e '.[ui]'", file=sys.stderr)
        return 1

    app_path = str(Path(__file__).resolve().parent.parent / "ui" / "streamlit_app.py")
    sys.argv = ["streamlit", "run", app_path, "--server.headless=true"]
    stcli.main()
    return 0


def _cmd_suggest_mappings(args: argparse.Namespace) -> int:
    from analysis.heuristics import discovered_heuristics
    from analysis.mapping_loader import load_curated_mappings

    try:
        from knowledge.embedder import SentenceTransformerEmbedder
    except ImportError:
        print("sentence-transformers is required. Install with: pip install -e '.[suggest]'", file=sys.stderr)
        return 1

    embedder = SentenceTransformerEmbedder()

    # Resolve heuristic info
    if args.rule_id:
        heuristics = discovered_heuristics()
        heuristic = next(
            (h for h in heuristics if h.rule_id == args.rule_id), None,
        )
        if not heuristic:
            print(f"Unknown rule_id: {args.rule_id}", file=sys.stderr)
            return 1
        query_text = f"{heuristic.name}. {heuristic.description}"
        target_frameworks = heuristic.frameworks
    else:
        query_text = args.description
        target_frameworks = ()

    from graph.neo4j_client import Neo4jClient, Neo4jConfig

    from analysis.mapping_engine import graphrag_score_suggestions

    try:
        config = Neo4jConfig.from_env()
    except ValueError:
        print("Neo4j credentials required. Set NEO4J_PASSWORD env var.", file=sys.stderr)
        return 1

    client = Neo4jClient(config)
    store = None
    try:
        from knowledge.index import TechniqueIndex
        from knowledge.store import TechniqueStore

        store = TechniqueStore()
        tech_idx = TechniqueIndex(store)
        curated = load_curated_mappings(args.rule_id or "AD-HOC", index=tech_idx) if args.rule_id else ()

        suggestions = graphrag_score_suggestions(
            rule_id=args.rule_id or "AD-HOC",
            heuristic_text=query_text,
            neo4j_client=client,
            embedder=embedder,
            curated_mappings=curated,
            target_frameworks=target_frameworks,
            top_k=args.top_k,
            threshold=args.threshold,
        )
    finally:
        if store:
            store.close()
        client.close()

    if not suggestions:
        print("No suggestions above threshold.")
        return 0

    if args.format == "json":
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
            print(f"rule_id = {toml_string(args.rule_id or 'AD-HOC')}")
            print(f"technique_id = {toml_string(s.technique_id)}")
            print(f"framework = {toml_string(s.framework)}")
            print(f"tactic = {toml_string(s.tactic)}")
            print(f"rationale = {toml_string(s.explanation)}")
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
    p_val.add_argument("--model", required=False, type=Path, help="Path to TOML model file")

    # load-graph
    p_lg = sub.add_parser("load-graph", help="Load canonical model into Neo4j")
    p_lg.add_argument("--model", required=False, type=Path, help="Path to canonical TOML model")
    p_lg.add_argument("--clear", action="store_true", help="Clear existing graph data first")

    # generate-threats
    p_gt = sub.add_parser("generate-threats", help="Generate structured threat outputs")
    p_gt.add_argument("--model", required=False, type=Path, help="Path to canonical TOML model")
    p_gt.add_argument("--output", type=Path, default=None, help="Output file path for threats JSON")
    p_gt.add_argument("--enrich", action="store_true", help="Enable GraphRAG threat enrichment (requires Neo4j)")

    # score-risks
    p_sr = sub.add_parser("score-risks", help="Score threats into prioritized risk records")
    p_sr.add_argument("--threats", type=Path, default=None, help="Path to threat report JSON")
    p_sr.add_argument("--output", type=Path, default=None, help="Output path for risk report JSON")

    # ui
    sub.add_parser("ui", help="Launch the Streamlit analyst interface")

    # session
    p_session = sub.add_parser("session", help="Inspect or update the shared CLI/UI session")
    p_session.add_argument("--model", type=Path, default=None, help="Set the active model path for the session")
    p_session.add_argument("--clear", action="store_true", help="Clear the persisted session")

    # sync
    p_sync = sub.add_parser("sync", help="Sync MITRE ATT&CK and ATLAS knowledge base")
    p_sync.add_argument("--attack-version", default="latest", help="ATT&CK version to fetch (default: latest)")
    p_sync.add_argument("--atlas-version", default="latest", help="ATLAS version to fetch (default: latest)")
    p_sync.add_argument("--offline", type=Path, default=None, help="Directory with local STIX/ATLAS files")
    p_sync.add_argument("--status", action="store_true", help="Show current sync status")
    p_sync.add_argument("--embed", action="store_true", help="Embed MITRE text chunks in Neo4j during sync (implies --neo4j)")
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
        "session": _cmd_session,
        "sync": _cmd_sync,
        "suggest-mappings": _cmd_suggest_mappings,
    }
    return dispatch[args.command](args)


def entry_point() -> None:
    raise SystemExit(main())
