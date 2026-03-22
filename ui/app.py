from __future__ import annotations

import tempfile
from pathlib import Path

import streamlit as st

from ui.actions import rebuild_analysis
from ui.data_access import list_example_models
from ui.pages import chat, model_overview, risks, threats

ROOT = Path(__file__).resolve().parents[1]


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


def main() -> None:
    st.set_page_config(page_title="Threat Forge AI", page_icon="TF", layout="wide")
    st.title("Threat Forge AI - MVP Analyst Interface")

    example_models = list_example_models(ROOT)
    example_labels = [path.name for path in example_models]
    selected_label = st.sidebar.selectbox("Example model", ["(none)", *example_labels], index=1 if example_labels else 0)
    selected_example = None if selected_label == "(none)" else next(path for path in example_models if path.name == selected_label)

    uploaded_model = st.sidebar.file_uploader("Upload model (.toml)", type=["toml"])
    model_path = _resolve_model_path(uploaded_model, selected_example)

    _render_pipeline_controls(model_path)

    page = st.sidebar.radio(
        "Screen",
        ["Model Overview", "Threats", "Risks", "Chat"],
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
    else:
        chat.render(ROOT)


if __name__ == "__main__":
    main()
