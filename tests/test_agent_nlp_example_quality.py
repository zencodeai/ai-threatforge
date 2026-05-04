from __future__ import annotations

import tomllib
from pathlib import Path

from agents.observability import NullTraceRecorder
from agents.tools import AgentTools
from agents.workflow import QueryWorkflow
from nlp_quality_fixtures import load_golden_fixture

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE_MODEL = ROOT / "examples" / "fintech_ai_platform.toml"


def _example_graph_runner() -> tuple[dict, callable]:
    model = tomllib.loads(EXAMPLE_MODEL.read_text(encoding="utf-8"))

    def _run(query_id: str, _params: dict | None) -> list[dict]:
        if query_id == "trust_boundary_crossings":
            return [
                {
                    "trust_boundary": tb["id"],
                    "from_domain": tb["from_domain"],
                    "to_domain": tb["to_domain"],
                }
                for tb in model["trust_boundaries"]
            ]

        if query_id == "dependency_edges":
            return [
                {
                    "source": dep["source"],
                    "target": dep["target"],
                    "relationship": dep["relationship"],
                }
                for dep in model["dependencies"]
            ]

        return [
            {
                "module_id": module["id"],
                "module_name": module["name"],
                "module_type": module["module_type"],
            }
            for module in model["modules"]
            if module.get("internet_exposed")
        ]

    return model, _run


def test_query_workflow_real_artifact_quality_metrics() -> None:
    _model, graph_runner = _example_graph_runner()
    workflow = QueryWorkflow(
        AgentTools(base_dir=ROOT, graph_runner=graph_runner),
        tracer=NullTraceRecorder(),
    )

    cases, thresholds = load_golden_fixture("example_golden.json")

    total = len(cases)
    answer_hits = 0
    tool_hits = 0
    forbidden_hits = 0
    evidence_hits = 0
    phrase_hits = 0
    clean_hits = 0
    failures: list[str] = []

    for case in cases:
        answer, state = workflow.answer(case.question)
        tool_names = {call.name for call in state.tool_calls}

        has_answer = bool(answer.answer.strip())
        has_tools = set(case.expected_tools).issubset(tool_names)
        avoids_forbidden = not any(tool in tool_names for tool in case.forbidden_tools)
        has_refs = all(
            any(ref.startswith(prefix) for ref in answer.evidence_refs)
            for prefix in case.required_ref_prefixes
        )
        has_phrases = all(phrase in answer.answer for phrase in case.required_answer_phrases)
        is_clean = case.allow_limitations or not answer.limitations

        answer_hits += int(has_answer)
        tool_hits += int(has_tools)
        forbidden_hits += int(avoids_forbidden)
        evidence_hits += int(has_refs)
        phrase_hits += int(has_phrases)
        clean_hits += int(is_clean)

        if not all((has_answer, has_tools, avoids_forbidden, has_refs, has_phrases, is_clean)):
            failures.append(
                f"{case.question!r}: "
                f"answer={has_answer} tools={has_tools} avoids_forbidden={avoids_forbidden} "
                f"refs={has_refs} phrases={has_phrases} clean={is_clean} "
                f"tool_names={sorted(tool_names)} refs={answer.evidence_refs} "
                f"limitations={answer.limitations} answer_text={answer.answer!r}"
            )

    metrics = {
        "answer_nonempty_rate": answer_hits / total,
        "expected_tool_coverage_rate": tool_hits / total,
        "forbidden_tool_avoidance_rate": forbidden_hits / total,
        "grounded_reference_rate": evidence_hits / total,
        "required_phrase_rate": phrase_hits / total,
        "clean_answer_rate": clean_hits / total,
    }

    metric_failures = [
        f"{name}={metrics[name]:.2f} < {minimum:.2f}"
        for name, minimum in thresholds.items()
        if metrics[name] < minimum
    ]

    assert not metric_failures, (
        "Real-artifact NLP query quality regression: "
        + ", ".join(metric_failures)
        + "\nCase failures:\n"
        + "\n".join(failures)
    )
