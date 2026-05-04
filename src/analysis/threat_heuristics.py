from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


Framework = Literal["ATTACK", "ATLAS"]


@dataclass(frozen=True)
class ThreatHeuristic:
    rule_id: str
    name: str
    description: str
    graph_pattern: str
    target_type: Literal["module", "workflow", "object", "datastore", "system"]
    severity_hint: Literal["low", "medium", "high", "critical"]
    frameworks: tuple[Framework, ...]
    output_field_mapping: tuple[str, ...]


# Auto-discovered from analysis.heuristics package
from .heuristics import discovered_heuristics

THREAT_HEURISTICS: tuple[ThreatHeuristic, ...] = discovered_heuristics()


def get_threat_heuristics() -> tuple[ThreatHeuristic, ...]:
    """Return immutable heuristic catalog used by the threat generation engine."""
    return THREAT_HEURISTICS
