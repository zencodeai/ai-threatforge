from __future__ import annotations

from analysis.technique_mapping import (
    RULE_TECHNIQUE_MAPPINGS,
    get_all_technique_mappings,
    get_rule_technique_mappings,
    map_rule_to_techniques,
    validate_mapping_coverage,
)
from analysis.threat_generation import THREAT_HEURISTICS


def test_every_rule_has_mapping() -> None:
    ok, message = validate_mapping_coverage()
    assert ok, message


def test_all_rule_ids_present_in_mapping_catalog() -> None:
    mapped_rule_ids = {mapping.rule_id for mapping in RULE_TECHNIQUE_MAPPINGS}
    expected_rule_ids = {rule.rule_id for rule in THREAT_HEURISTICS}
    assert expected_rule_ids.issubset(mapped_rule_ids)


def test_map_rule_to_techniques_returns_known_frameworks() -> None:
    mappings = map_rule_to_techniques("TH-004")

    frameworks = {mapping.framework for mapping in mappings}
    assert "ATLAS" in frameworks
    assert "ATTACK" in frameworks


def test_get_rule_technique_mappings_returns_empty_for_unknown_rule() -> None:
    assert get_rule_technique_mappings("TH-999") == ()


def test_mapping_entries_have_required_fields() -> None:
    for mapping in get_all_technique_mappings():
        assert mapping.rule_id.startswith("TH-")
        assert mapping.framework in {"ATTACK", "ATLAS"}
        assert mapping.technique_id
        assert mapping.technique_name
        assert mapping.tactic
        assert mapping.mapping_rationale
