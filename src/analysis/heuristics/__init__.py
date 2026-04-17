"""Auto-discovery of heuristic plugins.

Drop a ``th_*.py`` module into this package with a module-level ``HEURISTIC``
(:class:`~analysis.threat_generation.ThreatHeuristic`) and a materializer class
that satisfies the :class:`~analysis.materializer_registry.ThreatMaterializer`
protocol.  Both will be picked up automatically at import time.
"""

from __future__ import annotations

import importlib
import pkgutil
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..materializer_registry import ThreatMaterializer
    from ..threat_generation import ThreatHeuristic


def _discover() -> tuple[tuple[ThreatHeuristic, ...], list[ThreatMaterializer]]:
    heuristics: list[ThreatHeuristic] = []
    materializers: list[ThreatMaterializer] = []

    for _finder, name, _ispkg in pkgutil.iter_modules(__path__):
        if not name.startswith("th_"):
            continue
        mod = importlib.import_module(f".{name}", __package__)
        if hasattr(mod, "HEURISTIC"):
            heuristics.append(mod.HEURISTIC)
        # Find the first materializer class in the module
        for attr in vars(mod).values():
            if (
                isinstance(attr, type)
                and hasattr(attr, "rule_id")
                and hasattr(attr, "materialize")
                and attr.__module__ == mod.__name__
            ):
                materializers.append(attr())
                break

    heuristics.sort(key=lambda h: h.rule_id)
    materializers.sort(key=lambda m: m.rule_id)
    return tuple(heuristics), materializers


_heuristics, _materializers = _discover()


def discovered_heuristics() -> tuple[ThreatHeuristic, ...]:
    """Return all auto-discovered heuristic definitions."""
    return _heuristics


def discovered_materializers() -> list[ThreatMaterializer]:
    """Return instances of all auto-discovered materializer classes."""
    return list(_materializers)
