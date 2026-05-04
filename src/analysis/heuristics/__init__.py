"""Auto-discovery of heuristic plugins.

Drop a ``th_*.py`` module into this package **or** a ``rules/th_*.toml`` file
and both the :class:`~analysis.threat_heuristics.ThreatHeuristic` definition and
a matching materializer will be picked up automatically at import time.

Python modules take precedence when a rule_id is defined in both formats.
"""

from __future__ import annotations

import importlib
import pkgutil
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ..materializer_registry import ThreatMaterializer
    from ..threat_heuristics import ThreatHeuristic

__all__ = [
    "discovered_heuristics",
    "discovered_materializers",
]

_RULES_DIR = Path(__file__).resolve().parent / "rules"


# ------------------------------------------------------------------
# TOML loader
# ------------------------------------------------------------------

def _load_toml(path: Path) -> dict[str, Any]:
    """Load a TOML file using the stdlib tomllib (3.11+) or tomli fallback."""
    try:
        import tomllib  # type: ignore[import-untyped]
    except ModuleNotFoundError:  # pragma: no cover – Python < 3.11
        import tomli as tomllib  # type: ignore[no-redef]
    return tomllib.loads(path.read_text(encoding="utf-8"))


def _heuristic_from_toml(data: dict[str, Any]) -> ThreatHeuristic:
    from ..threat_heuristics import ThreatHeuristic

    h = data["heuristic"]
    return ThreatHeuristic(
        rule_id=h["rule_id"],
        name=h["name"],
        description=h["description"],
        graph_pattern=h["graph_pattern"],
        target_type=h["target_type"],
        severity_hint=h["severity_hint"],
        frameworks=tuple(h.get("frameworks", ())),
        output_field_mapping=tuple(h.get("output_field_mapping", ())),
    )


def _materializer_from_toml(
    rule_id: str,
    data: dict[str, Any],
) -> ThreatMaterializer:
    from .generic_materializer import GenericMaterializer

    return GenericMaterializer(rule_id, data["materializer"])


# ------------------------------------------------------------------
# Discovery
# ------------------------------------------------------------------

def _discover() -> tuple[tuple[ThreatHeuristic, ...], list[ThreatMaterializer]]:
    heuristics: dict[str, ThreatHeuristic] = {}
    materializers: dict[str, ThreatMaterializer] = {}

    # 1. TOML-defined rules (loaded first, may be overridden by Python)
    if _RULES_DIR.is_dir():
        for toml_path in sorted(_RULES_DIR.glob("th_*.toml")):
            data = _load_toml(toml_path)
            h = _heuristic_from_toml(data)
            heuristics[h.rule_id] = h
            materializers[h.rule_id] = _materializer_from_toml(h.rule_id, data)

    # 2. Python modules (override TOML when both exist)
    for _finder, name, _ispkg in pkgutil.iter_modules(__path__):
        if not name.startswith("th_"):
            continue
        mod = importlib.import_module(f".{name}", __package__)
        if hasattr(mod, "HEURISTIC"):
            heuristics[mod.HEURISTIC.rule_id] = mod.HEURISTIC
        # Find the first materializer class in the module
        for attr in vars(mod).values():
            if (
                isinstance(attr, type)
                and hasattr(attr, "rule_id")
                and hasattr(attr, "materialize")
                and attr.__module__ == mod.__name__
            ):
                materializers[attr.rule_id] = attr()
                break

    sorted_ids = sorted(heuristics)
    return (
        tuple(heuristics[rid] for rid in sorted_ids),
        [materializers[rid] for rid in sorted_ids if rid in materializers],
    )


_heuristics, _materializers = _discover()


def discovered_heuristics() -> tuple[ThreatHeuristic, ...]:
    """Return all auto-discovered heuristic definitions."""
    return _heuristics


def discovered_materializers() -> list[ThreatMaterializer]:
    """Return instances of all auto-discovered materializer classes."""
    return list(_materializers)
