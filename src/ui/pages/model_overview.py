from __future__ import annotations

from pathlib import Path

import streamlit as st

from ui.data_access import build_model_overview, list_example_models, load_model
from project_paths import ProjectPaths

ROOT = ProjectPaths.default().root


def render(model_path: Path) -> None:
    st.subheader("Model Overview")
    st.caption(f"Model source: `{model_path}`")

    try:
        model = load_model(model_path)
    except Exception as exc:
        st.error(f"Failed to load model: {exc}")
        return

    overview = build_model_overview(model)
    counts = overview["counts"]

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Domains", counts["domains"])
    c2.metric("Modules", counts["modules"])
    c3.metric("Objects", counts["objects"])
    c4.metric("Workflows", counts["workflows"])

    c5, c6, c7 = st.columns(3)
    c5.metric("Datastores", counts["datastores"])
    c6.metric("Trust Boundaries", counts["trust_boundaries"])
    c7.metric("Dependencies", counts["dependencies"])

    st.markdown("### System")
    st.json(
        {
            "model_id": overview["model_id"],
            "system": overview["system"],
            "criticality": overview["criticality"],
            "industry": overview["industry"],
            "schema_version": overview["schema_version"],
        }
    )

    st.markdown("### Modules")
    module_rows = [
        {
            "module_id": module.id,
            "name": module.name,
            "type": module.module_type,
            "domain": module.domain,
            "privilege": module.privilege,
            "internet_exposed": module.internet_exposed,
            "ai_relevant": module.ai_relevant,
        }
        for module in model.modules
    ]
    st.dataframe(module_rows, use_container_width=True)


def _default_model_path() -> Path | None:
    models = list_example_models(ROOT)
    return models[0] if models else None


def main() -> None:
    st.set_page_config(page_title="Threat Forge AI - Model Overview", page_icon="TF", layout="wide")
    model_path = _default_model_path()
    if model_path is None:
        st.info("No example model found in examples/.")
        return
    render(model_path)


if __name__ == "__main__":
    main()
