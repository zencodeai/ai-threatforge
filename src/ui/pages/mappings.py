from __future__ import annotations

from pathlib import Path

import streamlit as st

from project_paths import ProjectPaths
from ui.data_access import (
    curated_mapping_rows,
    heuristic_rows,
    load_mapping_config,
    promote_suggestion,
    save_mapping_config,
    suggested_mapping_rows,
)

ROOT = ProjectPaths.default().root


def _unique_rule_ids(rows: list[dict]) -> list[str]:
    """Extract sorted unique rule_ids from mapping rows."""
    return sorted({r["rule_id"] for r in rows})


def _render_curated_tab() -> None:
    rows = curated_mapping_rows()
    rule_ids = _unique_rule_ids(rows)

    col1, col2 = st.columns([1, 3])
    with col1:
        selected_rule = st.selectbox(
            "Filter by rule_id",
            ["All", *rule_ids],
            key="curated_rule_filter",
        )
    with col2:
        frameworks = sorted({r["framework"] for r in rows})
        selected_fw = st.selectbox(
            "Filter by framework",
            ["All", *frameworks],
            key="curated_fw_filter",
        )

    filtered = rows
    if selected_rule != "All":
        filtered = [r for r in filtered if r["rule_id"] == selected_rule]
    if selected_fw != "All":
        filtered = [r for r in filtered if r["framework"] == selected_fw]

    st.metric("Curated Mappings", len(filtered))
    if filtered:
        st.dataframe(filtered, use_container_width=True)
    else:
        st.info("No curated mappings found.")


def _render_suggested_tab() -> None:
    rows = suggested_mapping_rows()
    if not rows:
        st.info(
            "No suggested mappings found. Run **Sync Now** with "
            "**Map heuristics** enabled to generate suggestions."
        )
        return

    rule_ids = _unique_rule_ids(rows)

    col1, col2 = st.columns([1, 3])
    with col1:
        selected_rule = st.selectbox(
            "Filter by rule_id",
            ["All", *rule_ids],
            key="suggested_rule_filter",
        )
    with col2:
        sort_order = st.selectbox(
            "Sort by",
            ["Score (high → low)", "Score (low → high)", "Rule ID"],
            key="suggested_sort",
        )

    filtered = rows
    if selected_rule != "All":
        filtered = [r for r in filtered if r["rule_id"] == selected_rule]
    if sort_order == "Score (high → low)":
        filtered = sorted(filtered, key=lambda r: -r["composite_score"])
    elif sort_order == "Score (low → high)":
        filtered = sorted(filtered, key=lambda r: r["composite_score"])
    else:
        filtered = sorted(filtered, key=lambda r: (r["rule_id"], -r["composite_score"]))

    st.metric("Suggested Mappings", len(filtered))
    st.dataframe(filtered, use_container_width=True)

    # ── Promote controls ─────────────────────────────────────────
    st.markdown("#### Promote a suggestion to curated")
    pcol1, pcol2, pcol3 = st.columns([1, 1, 1])
    with pcol1:
        promote_rule = st.selectbox("Rule ID", rule_ids, key="promote_rule")
    with pcol2:
        rule_techniques = sorted({
            r["technique_id"]
            for r in rows
            if r["rule_id"] == promote_rule
        })
        promote_tech = st.selectbox("Technique ID", rule_techniques, key="promote_tech")
    with pcol3:
        st.write("")  # spacing
        st.write("")
        if st.button("Promote", type="primary", key="promote_btn"):
            st.session_state["_pending_promote"] = (promote_rule, promote_tech)

    pending = st.session_state.get("_pending_promote")
    if pending:
        rule, tech = pending
        st.warning(f"Promote **{rule} → {tech}** to curated mappings?")
        ccol1, ccol2 = st.columns(2)
        with ccol1:
            if st.button("Confirm", key="promote_confirm"):
                ok = promote_suggestion(rule, tech)
                st.session_state.pop("_pending_promote", None)
                if ok:
                    st.success(f"Promoted {rule} → {tech} to curated.")
                    st.rerun()
                else:
                    st.error(f"Suggestion {rule} → {tech} not found.")
        with ccol2:
            if st.button("Cancel", key="promote_cancel"):
                st.session_state.pop("_pending_promote", None)
                st.rerun()


def _render_heuristics_tab() -> None:
    rows = heuristic_rows()
    st.metric("Discovered Heuristics", len(rows))
    if rows:
        st.dataframe(rows, use_container_width=True)
    else:
        st.info("No heuristics discovered.")


def _render_config_editor() -> None:
    with st.expander("Mapping Configuration", expanded=False):
        config = load_mapping_config()
        expansion = config.get("expansion", {})
        suggestions = config.get("suggestions", {})

        st.markdown("##### Expansion (Layer 2)")
        exp_enabled = st.toggle(
            "Enable tactic-based expansion",
            value=expansion.get("enabled", False),
            key="cfg_exp_enabled",
        )

        st.markdown("##### Suggestions (Layer 0)")
        sug_included = st.toggle(
            "Include suggested mappings in analysis",
            value=suggestions.get("include_suggested", False),
            key="cfg_sug_included",
        )

        if st.button("Save Config", key="save_config_btn"):
            config["expansion"]["enabled"] = exp_enabled
            config["suggestions"]["include_suggested"] = sug_included
            save_mapping_config(config)
            st.success("Configuration saved.")
            st.rerun()


def render(base_dir: Path) -> None:
    st.subheader("Mappings")
    st.caption("Browse curated and suggested technique mappings, discover heuristics.")

    tab_curated, tab_suggested, tab_heuristics = st.tabs(
        ["Curated", "Suggested", "Heuristics"]
    )

    with tab_curated:
        _render_curated_tab()
    with tab_suggested:
        _render_suggested_tab()
    with tab_heuristics:
        _render_heuristics_tab()

    _render_config_editor()


def main() -> None:
    st.set_page_config(page_title="Threat Forge AI - Mappings", page_icon="TF", layout="wide")
    render(ROOT)


if __name__ == "__main__":
    main()
