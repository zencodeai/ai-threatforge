from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "nlp_quality"


@dataclass(frozen=True)
class QueryEvalCase:
    question: str
    expected_tools: tuple[str, ...]
    required_answer_phrases: tuple[str, ...]
    required_ref_prefixes: tuple[str, ...]
    forbidden_tools: tuple[str, ...] = ()
    allow_limitations: bool = False


def load_golden_fixture(name: str) -> tuple[list[QueryEvalCase], dict[str, float]]:
    payload = json.loads((FIXTURE_DIR / name).read_text(encoding="utf-8"))
    cases = [
        QueryEvalCase(
            question=entry["question"],
            expected_tools=tuple(entry["expected_tools"]),
            required_answer_phrases=tuple(entry["required_answer_phrases"]),
            required_ref_prefixes=tuple(entry["required_ref_prefixes"]),
            forbidden_tools=tuple(entry.get("forbidden_tools", ())),
            allow_limitations=entry.get("allow_limitations", False),
        )
        for entry in payload["cases"]
    ]
    thresholds = {key: float(value) for key, value in payload["thresholds"].items()}
    return cases, thresholds
