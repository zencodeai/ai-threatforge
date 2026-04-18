from __future__ import annotations

import tempfile
from pathlib import Path

import streamlit as st

from project_paths import ProjectPaths
from ui.actions import rebuild_analysis, sync_knowledge
from ui.data_access import list_example_models, load_sync_status
from ui.pages import chat, mappings, model_overview, risks, threats

ROOT = ProjectPaths.default().root


def _resolve_model_path(uploaded_file, selected_example: Path | None) -> Path | None:
    if uploaded_file is not None:
        suffix = Path(uploaded_file.name).suffix or ".toml"
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
            tmp.write(uploaded_file.getvalue())
            return Path(tmp.name)
    return selected_example


def _render_pipeline_controls(model_path: Path | None) -> None:
    st.sidebar.markdown("### Rebuild Analysis")
    clear_graph = st.sidebar.checkbox("Clear graph before load", value=True)

    if st.sidebar.button("Run Rebuild Workflow"):
        if model_path is None:
            st.sidebar.error("Select or upload a model first.")
            return

        with st.spinner("Running analysis workflow..."):
            step_results = rebuild_analysis(model_path, clear_graph=clear_graph)

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

    if status.get("status") == "not synced":
        st.sidebar.info("Knowledge base not synced yet.")
    else:
        col1, col2 = st.sidebar.columns(2)
        col1.metric("ATT&CK", status.get("attack_version", "—"))
        col2.metric("ATLAS", status.get("atlas_version", "—"))
        col3, col4 = st.sidebar.columns(2)
        col3.metric("Techniques", status.get("technique_count", "0"))
        col4.metric("Embeddings", status.get("embedding_count", "0"))
        st.sidebar.metric("Suggestions", status.get("suggestion_count", "0"))
        last_sync = status.get("last_sync_utc", "never")
        if len(last_sync) > 16:
            last_sync = last_sync[:16]
        st.sidebar.caption(f"Last sync: {last_sync}")

    with st.sidebar.expander("Sync Options", expanded=False):
        attack_ver = st.text_input("ATT&CK version", value="latest", key="sync_attack_ver")
        atlas_ver = st.text_input("ATLAS version", value="latest", key="sync_atlas_ver")
        embed = st.checkbox("Generate embeddings", key="sync_embed")
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
