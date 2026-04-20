from __future__ import annotations

from pathlib import Path

import streamlit as st

from ui.data_access import (
    load_threat_report,
    mitigation_rows,
    related_technique_rows,
    threat_rows,
)
from project_paths import ProjectPaths

ROOT = ProjectPaths.default().root


def _severity_color(severity: str) -> str:
    return {
        "critical": "red",
        "high": "orange",
        "medium": "blue",
        "low": "green",
    }.get(severity, "gray")


def render(base_dir: Path) -> None:
    st.subheader("Threats")

    report, source_path = load_threat_report(base_dir=base_dir)
    if report is None or source_path is None:
        st.info("No threat report found. Run Rebuild Analysis to generate threat artifacts.")
        return

    st.caption(f"Threat artifact: `{source_path}`")

    # ── Summary metrics ──────────────────────────────────────────
    enriched_count = sum(
        1 for t in report.threats
        if t.suggested_mitigations or t.related_techniques
    )
    col1, col2, col3 = st.columns(3)
    col1.metric("Total Threats", report.threat_count)
    col2.metric("Enriched", enriched_count)
    col3.metric(
        "Suggested Mitigations",
        sum(len(t.suggested_mitigations) for t in report.threats),
    )

    # ── Filters ──────────────────────────────────────────────────
    severities = sorted({t.severity_hint for t in report.threats})
    rule_ids = sorted({t.rule_id for t in report.threats})

    fcol1, fcol2, fcol3 = st.columns([1, 1, 2])
    with fcol1:
        sel_severity = st.selectbox(
            "Severity", ["All", *severities], key="threat_sev_filter",
        )
    with fcol2:
        sel_rule = st.selectbox(
            "Rule ID", ["All", *rule_ids], key="threat_rule_filter",
        )
    with fcol3:
        only_enriched = st.checkbox(
            "Only enriched threats", key="threat_enriched_filter",
        )

    filtered = report.threats
    if sel_severity != "All":
        filtered = [t for t in filtered if t.severity_hint == sel_severity]
    if sel_rule != "All":
        filtered = [t for t in filtered if t.rule_id == sel_rule]
    if only_enriched:
        filtered = [
            t for t in filtered
            if t.suggested_mitigations or t.related_techniques
        ]

    # ── Threat table ─────────────────────────────────────────────
    rows = threat_rows(report)
    # Re-filter rows to match
    filtered_ids = {t.threat_id for t in filtered}
    display_rows = [r for r in rows if r["threat_id"] in filtered_ids]

    st.caption(f"Showing {len(display_rows)} of {report.threat_count} threats")
    st.dataframe(display_rows, use_container_width=True)

    # ── Threat detail expanders ──────────────────────────────────
    for threat in filtered:
        has_enrichment = bool(
            threat.suggested_mitigations or threat.related_techniques
        )
        enrichment_tag = " [enriched]" if has_enrichment else ""
        label = (
            f":{_severity_color(threat.severity_hint)}[{threat.severity_hint.upper()}] "
            f"**{threat.threat_id}** — {threat.title}{enrichment_tag}"
        )

        with st.expander(label, expanded=False):
            st.markdown(f"**Rule:** {threat.rule_id} | "
                        f"**Target:** {threat.target_id} ({threat.target_type}) | "
                        f"**Severity:** {threat.severity_hint}")
            st.markdown(threat.description)

            # Framework mappings
            if threat.framework_mappings:
                st.markdown("##### Framework Mappings")
                mapping_data = [
                    {
                        "technique_id": m.technique_id,
                        "technique_name": m.technique_name,
                        "framework": m.framework,
                        "tactic": m.tactic,
                        "mapping_type": m.mapping_type,
                    }
                    for m in threat.framework_mappings
                ]
                st.dataframe(mapping_data, use_container_width=True)

            # Suggested mitigations
            if threat.suggested_mitigations:
                st.markdown("##### Suggested Mitigations")
                st.dataframe(
                    mitigation_rows(threat), use_container_width=True,
                )
            elif has_enrichment:
                st.caption("No mitigation gaps found for mapped techniques.")

            # Related techniques
            if threat.related_techniques:
                st.markdown("##### Related Techniques")
                st.dataframe(
                    related_technique_rows(threat), use_container_width=True,
                )

            # Evidence
            if threat.evidence:
                with st.expander("Evidence", expanded=False):
                    st.json(threat.evidence)


def main() -> None:
    st.set_page_config(page_title="Threat Forge AI - Threats", page_icon="TF", layout="wide")
    render(ROOT)


if __name__ == "__main__":
    main()
