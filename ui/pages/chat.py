from __future__ import annotations

from pathlib import Path

import streamlit as st

from agents.tools import AgentTools
from agents.workflow import QueryWorkflow


SAMPLE_QUESTIONS = [
    "What are the highest risks right now?",
    "Show threats for module api_gateway",
    "Which trust boundary crossings are present?",
    "What does technique T1190 map to?",
    "Explain ATLAS-relevant AI threats.",
]


def render(base_dir: Path) -> None:
    st.subheader("Analyst Chat")
    st.caption("Ask natural-language questions grounded in graph, threats, risks, and mappings.")

    tools = AgentTools(base_dir=base_dir)
    workflow = QueryWorkflow(tools=tools)

    selected = st.selectbox("Sample questions", ["(custom)", *SAMPLE_QUESTIONS], index=0)
    default_text = "" if selected == "(custom)" else selected
    question = st.text_input("Question", value=default_text, placeholder="Ask about risks, threats, techniques, or graph evidence")

    if st.button("Run Query", type="primary"):
        if not question.strip():
            st.warning("Enter a question before running the query.")
            return

        answer, state = workflow.answer(question.strip())

        st.markdown("### Answer")
        st.write(answer.answer)

        st.markdown("### Evidence References")
        if answer.evidence_refs:
            st.write(answer.evidence_refs)
        else:
            st.write("No evidence references returned.")

        if answer.limitations:
            st.markdown("### Limitations")
            st.write(answer.limitations)

        with st.expander("Tool Calls", expanded=False):
            st.json([call.model_dump() for call in state.tool_calls])
