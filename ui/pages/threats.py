from __future__ import annotations

from pathlib import Path

import streamlit as st

from ui.data_access import load_threat_report, threat_rows

ROOT = Path(__file__).resolve().parents[2]


def render(base_dir: Path) -> None:
    st.subheader("Threats")

    report, source_path = load_threat_report(base_dir=base_dir)
    if report is None or source_path is None:
        st.info("No threat report found. Run Rebuild Analysis to generate threat artifacts.")
        return

    st.caption(f"Threat artifact: `{source_path}`")
    st.metric("Threat Count", report.threat_count)

    rows = threat_rows(report)
    st.dataframe(rows, use_container_width=True)

    with st.expander("Raw threat report JSON", expanded=False):
        st.json(report.model_dump())


def main() -> None:
    st.set_page_config(page_title="Threat Forge AI - Threats", page_icon="TF", layout="wide")
    render(ROOT)


if __name__ == "__main__":
    main()
