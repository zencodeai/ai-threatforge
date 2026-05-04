"""Config-driven materializer that produces ThreatRecords from TOML definitions.

A single :class:`GenericMaterializer` instance replaces a hand-coded
materializer class.  The behaviour is driven entirely by the ``[materializer]``
section of a TOML rule file.  The class satisfies the
:class:`~analysis.materializer_registry.ThreatMaterializer` protocol.
"""

from __future__ import annotations

from typing import Any

from models.schema.canonical_model import CanonicalModel
from models.schema.threat_model import ThreatRecord

from ..threat_heuristics import ThreatHeuristic

__all__ = ["GenericMaterializer"]


class GenericMaterializer:
    """Turn a TOML materializer config into concrete :class:`ThreatRecord` items."""

    def __init__(self, rule_id: str, config: dict[str, Any]) -> None:
        self.rule_id = rule_id
        self._cfg = config
        self.required_snapshot_keys = self._infer_required_snapshot_keys(config)

    # ------------------------------------------------------------------
    # Protocol entry-point
    # ------------------------------------------------------------------

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
    ) -> list[ThreatRecord]:
        cfg = self._cfg
        primary_key: str = cfg["primary"]
        sort_fields: list[str] = cfg["sort_by"]
        skip_field: str | None = cfg.get("skip_if_empty")
        target_field: str = cfg["target_id_field"]
        id_fields: list[str] = cfg["id_fields"]
        rationale: str = cfg["rationale"]
        evidence_map: dict[str, str] = cfg.get("evidence", {})
        affected_cfg: dict[str, Any] = cfg.get("affected", {})
        filter_cfg: dict[str, Any] | None = cfg.get("filter")
        collect_cfgs: dict[str, dict[str, Any]] = cfg.get("collect", {})
        join_cfgs: dict[str, dict[str, Any]] = cfg.get("join", {})

        # -- Pre-compute collected aggregates --------------------------------
        collected = _precompute_collect(collect_cfgs, snapshot, sorted_unique_fn)

        # -- Sort primary rows -----------------------------------------------
        rows = sorted(
            snapshot.get(primary_key, []),
            key=lambda x: tuple(x.get(f, "") for f in sort_fields),
        )

        threats: list[ThreatRecord] = []
        for row in rows:
            # Skip check
            if skip_field and not row.get(skip_field, ""):
                continue

            # Filter check
            if filter_cfg:
                field_val = row.get(filter_cfg["field"], "")
                if field_val not in set(filter_cfg["in"]):
                    continue

            # Per-row join results
            joined = _compute_joins(
                join_cfgs, row, target_field, snapshot, sorted_unique_fn,
            )

            # Stable threat ID
            id_values = [row.get(f, "") for f in id_fields]
            threat_id = stable_id_fn(rule.rule_id, *id_values)

            # Evidence dict
            evidence = {
                key: _resolve_ref(ref, row, collected, joined)
                for key, ref in evidence_map.items()
            }

            # Affected lists
            affected_workflows = _resolve_affected(
                affected_cfg.get("workflows", []), row, collected, joined,
            )
            affected_objects = _resolve_affected(
                affected_cfg.get("objects", []), row, collected, joined,
            )

            threats.append(
                ThreatRecord(
                    threat_id=threat_id,
                    model_id=model.meta.model_id,
                    rule_id=rule.rule_id,
                    title=rule.name,
                    description=rule.description,
                    target_id=row.get(target_field, ""),
                    target_type=rule.target_type,
                    severity_hint=rule.severity_hint,
                    framework_mappings=technique_refs_fn(rule.rule_id),
                    rationale=rationale,
                    evidence=evidence,
                    affected_workflows=affected_workflows,
                    affected_objects=affected_objects,
                    created_at=now,
                )
            )
        return threats

    @staticmethod
    def _infer_required_snapshot_keys(config: dict[str, Any]) -> tuple[str, ...]:
        keys: list[str] = []

        primary = config.get("primary")
        if primary:
            keys.append(primary)

        for collect_cfg in config.get("collect", {}).values():
            source = collect_cfg.get("source")
            if source:
                keys.append(source)

        for join_cfg in config.get("join", {}).values():
            source = join_cfg.get("source")
            if source:
                keys.append(source)

        return tuple(dict.fromkeys(keys))


# ------------------------------------------------------------------
# Internal helpers
# ------------------------------------------------------------------


def _precompute_collect(
    collect_cfgs: dict[str, dict[str, Any]],
    snapshot: dict[str, list[dict[str, Any]]],
    sorted_unique_fn: Any,
) -> dict[str, dict[str, Any]]:
    """Pre-aggregate data from secondary snapshot keys."""
    collected: dict[str, dict[str, Any]] = {}
    for name, ccfg in collect_cfgs.items():
        source_rows = snapshot.get(ccfg["source"], [])
        unique_field = ccfg.get("unique_field")
        flatten_field = ccfg.get("flatten_field")

        unique_values: list[str] = []
        flattened_values: list[str] = []

        if unique_field:
            unique_values = sorted_unique_fn(
                [r.get(unique_field, "") for r in source_rows],
            )
        if flatten_field:
            flattened_values = sorted_unique_fn(
                [item for r in source_rows for item in r.get(flatten_field, [])],
            )

        collected[name] = {
            "unique_values": unique_values,
            "flattened_values": flattened_values,
            "unique_count": len(unique_values),
        }
    return collected


def _compute_joins(
    join_cfgs: dict[str, dict[str, Any]],
    row: dict[str, Any],
    target_field: str,
    snapshot: dict[str, list[dict[str, Any]]],
    sorted_unique_fn: Any,
) -> dict[str, dict[str, Any]]:
    """Compute per-row join results against secondary snapshot keys."""
    joined: dict[str, dict[str, Any]] = {}
    for name, jcfg in join_cfgs.items():
        source_rows = snapshot.get(jcfg["source"], [])
        match_value_field = jcfg.get("match_value_field", target_field)
        match_in = jcfg["match_in"]
        collect_field = jcfg["collect"]

        match_value = row.get(match_value_field, "")
        matched = sorted_unique_fn(
            [
                r.get(collect_field, "")
                for r in source_rows
                if r.get(collect_field)
                and match_value in r.get(match_in, [])
            ],
        )
        joined[name] = {"matched_keys": matched}
    return joined


def _resolve_ref(
    ref: Any,
    row: dict[str, Any],
    collected: dict[str, dict[str, Any]],
    joined: dict[str, dict[str, Any]],
) -> Any:
    """Resolve a single evidence reference to its runtime value."""
    if not isinstance(ref, str):
        return ref
    if ref.startswith("row."):
        return row.get(ref[4:])
    if ref.startswith("$"):
        parts = ref[1:].split(".", 1)
        if len(parts) == 2:
            name, attr = parts
            if name in collected:
                return collected[name].get(attr)
            if name in joined:
                return joined[name].get(attr)
    return ref


def _resolve_affected(
    cfg: Any,
    row: dict[str, Any],
    collected: dict[str, dict[str, Any]],
    joined: dict[str, dict[str, Any]],
) -> list[str]:
    """Resolve an affected_workflows / affected_objects config to a list."""
    if isinstance(cfg, str):
        if cfg.startswith("$"):
            parts = cfg[1:].split(".", 1)
            if len(parts) == 2:
                name, attr = parts
                if name in collected:
                    return collected[name].get(attr, [])
                if name in joined:
                    return joined[name].get(attr, [])
        return []

    if isinstance(cfg, list):
        if not cfg:
            return []
        result: list[str] = []
        for item in cfg:
            if isinstance(item, str) and item.startswith("row."):
                val = row.get(item[4:], "")
                if val:
                    result.append(val)
            elif isinstance(item, str) and item.startswith("$"):
                resolved = _resolve_affected(item, row, collected, joined)
                result.extend(resolved)
            elif isinstance(item, str) and item:
                result.append(item)
        return result

    return []
