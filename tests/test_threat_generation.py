from __future__ import annotations

from analysis.threat_heuristics import THREAT_HEURISTICS, get_threat_heuristics


def test_heuristic_catalog_has_minimum_rules() -> None:
    assert len(THREAT_HEURISTICS) >= 14


def test_rule_ids_are_unique() -> None:
    ids = [rule.rule_id for rule in THREAT_HEURISTICS]
    assert len(ids) == len(set(ids))


def test_every_rule_has_output_field_mapping() -> None:
    for rule in THREAT_HEURISTICS:
        assert rule.output_field_mapping
        assert all("<-" in mapping for mapping in rule.output_field_mapping)


def test_catalog_accessor_returns_same_rules() -> None:
    assert get_threat_heuristics() == THREAT_HEURISTICS


def test_framework_coverage_includes_attack_and_atlas() -> None:
    frameworks = {framework for rule in THREAT_HEURISTICS for framework in rule.frameworks}
    assert "ATTACK" in frameworks
    assert "ATLAS" in frameworks
