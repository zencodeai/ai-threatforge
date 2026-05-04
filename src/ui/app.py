from __future__ import annotations

import os
from pathlib import Path

import streamlit as st

from project_paths import ProjectPaths
from session_store import SessionStore
from ui.actions import rebuild_analysis, sync_knowledge
from ui.data_access import list_example_models, load_active_session, load_sync_status
from ui.pages import chat, mappings, model_overview, risks, threats

PATHS = ProjectPaths.default()
ROOT = PATHS.root
SESSION_STORE = SessionStore(PATHS)


def _resolve_model_path(uploaded_file, selected_example: Path | None) -> Path | None:
    if uploaded_file is not None:
        saved = SESSION_STORE.set_uploaded_model(uploaded_file.name, uploaded_file.getvalue())
        SESSION_STORE.set_model(saved)
        return saved
    if selected_example is not None:
        SESSION_STORE.set_model(selected_example)
        return selected_example
    return SESSION_STORE.resolve_model_path()


def _graphrag_available() -> bool:
    """Check if GraphRAG is enabled via env var."""
    return os.environ.get("THREATFORGE_GRAPHRAG", "") == "1"


def _render_pipeline_controls(model_path: Path | None) -> None:
    st.sidebar.markdown("### Rebuild Analysis")
    session = load_active_session(paths=PATHS)
    if session.get("model_path"):
        st.sidebar.caption(f"Session model: `{session['model_path']}`")
    clear_graph = st.sidebar.checkbox("Clear graph before load", value=True)
    enrich = st.sidebar.checkbox(
        "GraphRAG enrichment",
        value=False,
        key="rebuild_enrich",
        help="Add suggested mitigations and related techniques via Neo4j graph traversal.",
    )

    if st.sidebar.button("Run Rebuild Workflow"):
        if model_path is None:
            st.sidebar.error("Select or upload a model first.")
            return

        with st.spinner("Running analysis workflow..."):
            step_results = rebuild_analysis(
                model_path, clear_graph=clear_graph, enrich=enrich,
            )

        for step_name, result in step_results:
            if result.ok:
                st.sidebar.success(f"{step_name}: ok")
            else:
                st.sidebar.error(f"{step_name}: failed")
            with st.sidebar.expander(f"{step_name} output", expanded=False):
                st.code(result.stdout or "(no stdout)")
                if result.stderr:
                    st.code(result.stderr)


def _render_knowledge_status() -> None:
    st.sidebar.markdown("### Knowledge Base")
    status = load_sync_status()
    session = load_active_session(paths=PATHS)

    if session.get("threat_report_path") or session.get("risk_report_path"):
        st.sidebar.caption(
            "Session artifacts: "
            f"threats={session.get('threat_report_path') or '—'} · "
            f"risks={session.get('risk_report_path') or '—'}"
        )

    graphrag_on = _graphrag_available()
    if graphrag_on:
        st.sidebar.caption("GraphRAG: enabled")
    else:
        st.sidebar.caption("GraphRAG: off (set THREATFORGE_GRAPHRAG=1)")

    if status.get("status") == "not synced":
        st.sidebar.info("Knowledge base not synced yet.")
    else:
        col1, col2 = st.sidebar.columns(2)
        col1.metric("ATT&CK", status.get("attack_version", "—"))
        col2.metric("ATLAS", status.get("atlas_version", "—"))
        col3, col4 = st.sidebar.columns(2)
        col3.metric("Techniques", status.get("technique_count", "0"))
        col4.metric("Text Chunks", status.get("text_chunk_count", "0"))
        st.sidebar.metric("Suggestions", status.get("suggestion_count", "0"))
        last_sync = status.get("last_sync_utc", "never")
        if len(last_sync) > 16:
            last_sync = last_sync[:16]
        st.sidebar.caption(f"Last sync: {last_sync}")

    with st.sidebar.expander("Sync Options", expanded=False):
        attack_ver = st.text_input("ATT&CK version", value="latest", key="sync_attack_ver")
        atlas_ver = st.text_input("ATLAS version", value="latest", key="sync_atlas_ver")
        embed = st.checkbox(
            "Embed text chunks in Neo4j",
            key="sync_embed",
            help="Runs the chunking pipeline and stores vectorized TextChunk nodes in Neo4j.",
        )
        map_heuristics = st.checkbox("Map heuristics", key="sync_map_heuristics")
        threshold = st.slider(
            "Threshold", 0.10, 0.90, 0.40, 0.05,
            key="sync_threshold",
            disabled=not map_heuristics,
        )
        top_k = st.slider(
            "Top-k", 1, 30, 10,
            key="sync_top_k",
            disabled=not map_heuristics,
        )

        if st.button("Run Sync", key="run_sync_btn"):
            with st.spinner("Syncing knowledge base..."):
                result = sync_knowledge(
                    attack_version=attack_ver,
                    atlas_version=atlas_ver,
                    embed=embed or map_heuristics,
                    map_heuristics=map_heuristics,
                    map_threshold=threshold,
                    map_top_k=top_k,
                )
            if result.ok:
                st.success("Sync complete.")
                st.rerun()
            else:
                st.error("Sync failed.")
            st.code(result.stdout or "(no stdout)")
            if result.stderr:
                st.code(result.stderr)


def main() -> None:
    st.set_page_config(page_title="Threat Forge AI", page_icon="TF", layout="wide")
    st.title("Threat Forge AI - MVP Analyst Interface")

    example_models = list_example_models(ROOT)
    example_labels = [path.name for path in example_models]
    selected_label = st.sidebar.selectbox("Example model", ["(none)", *example_labels], index=1 if example_labels else 0)
    selected_example = None if selected_label == "(none)" else next(path for path in example_models if path.name == selected_label)

    uploaded_model = st.sidebar.file_uploader("Upload model (.toml)", type=["toml"])
    model_path = _resolve_model_path(uploaded_model, selected_example)

    _render_knowledge_status()
    _render_pipeline_controls(model_path)

    page = st.sidebar.radio(
        "Screen",
        ["Model Overview", "Threats", "Risks", "Mappings", "Chat"],
        index=0,
    )

    if page == "Model Overview":
        if model_path is None:
            st.info("Choose an example model or upload a TOML file to continue.")
        else:
            model_overview.render(model_path)
    elif page == "Threats":
        threats.render(ROOT)
    elif page == "Risks":
        risks.render(ROOT)
    elif page == "Mappings":
        mappings.render(ROOT)
    else:
        chat.render(ROOT)


if __name__ == "__main__":
    main()
