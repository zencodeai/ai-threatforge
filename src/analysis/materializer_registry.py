from __future__ import annotations

from typing import Any, Protocol

from models.schema.canonical_model import CanonicalModel
from models.schema.threat_model import ThreatRecord

from .threat_generation import ThreatHeuristic


class ThreatMaterializer(Protocol):
    """Protocol for turning a graph snapshot row into threat records for a single heuristic."""

    rule_id: str
    required_snapshot_keys: tuple[str, ...]

    def materialize(
        self,
        rule: ThreatHeuristic,
        model: CanonicalModel,
        snapshot: dict[str, list[dict[str, Any]]],
        *,
        now: str,
        technique_refs_fn: Any,
        stable_id_fn: Any,
        sorted_unique_fn: Any,
    ) -> list[ThreatRecord]: ...


_REGISTRY: dict[str, ThreatMaterializer] = {}
_discovered = False


def register_materializer(materializer: ThreatMaterializer) -> ThreatMaterializer:
    _REGISTRY[materializer.rule_id] = materializer
    return materializer


def auto_discover() -> None:
    """Discover and register all materializers from the heuristics package."""
    global _discovered
    if _discovered:
        return
    from .heuristics import discovered_materializers
    for m in discovered_materializers():
        register_materializer(m)
    _discovered = True


def get_materializer(rule_id: str) -> ThreatMaterializer:
    return _REGISTRY[rule_id]


def registered_rule_ids() -> frozenset[str]:
    return frozenset(_REGISTRY)


def all_materializers() -> list[ThreatMaterializer]:
    return list(_REGISTRY.values())
