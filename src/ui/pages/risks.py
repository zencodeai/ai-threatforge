from __future__ import annotations

from pathlib import Path

import streamlit as st

from ui.report_data import load_risk_report, risk_rows


def render(base_dir: Path) -> None:
    st.subheader("Risks")

    report, source_path = load_risk_report(base_dir=base_dir)
    if report is None or source_path is None:
        st.info("No risk report found. Run Rebuild Analysis to generate risk artifacts.")
        return

    st.caption(f"Risk artifact: `{source_path}`")
    st.metric("Risk Count", report.risk_count)

    rows = risk_rows(report)
    st.dataframe(rows, use_container_width=True)

    with st.expander("Raw risk report JSON", expanded=False):
        st.json(report.model_dump())


def main() -> None:
    st.set_page_config(page_title="Threat Forge AI - Risks", page_icon="TF", layout="wide")
    from project_paths import ProjectPaths

    render(ProjectPaths.default().root)


if __name__ == "__main__":
    main()
