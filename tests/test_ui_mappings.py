"""Tests for mapping/sync UI features: data_access helpers, actions, and page smoke."""

from __future__ import annotations

from pathlib import Path

import pytest

from ui.ui_actions import ActionResult, get_sync_status, sync_knowledge
from ui.mapping_data import (
    curated_mapping_rows,
    heuristic_rows,
    load_mapping_config,
    load_sync_status,
    promote_suggestion,
    save_mapping_config,
    suggested_mapping_rows,
)


# ── Fixtures ─────────────────────────────────────────────────────

CURATED_TOML = """\
# Test curated rules

[[mappings]]
rule_id = "TH-001"
technique_id = "T1190"
framework = "ATTACK"
tactic = "initial-access"
rationale = "Test rationale A."

[[mappings]]
rule_id = "TH-001"
technique_id = "T1078"
framework = "ATTACK"
tactic = "defense-evasion"
rationale = "Test rationale B."

[[mappings]]
rule_id = "TH-004"
technique_id = "AML.T0016"
framework = "ATLAS"
tactic = "ml-attack-staging"
rationale = "Test rationale C."
"""

SUGGESTED_TOML = """\
# Auto-generated suggestions

[[mappings]]
rule_id = "TH-001"
technique_id = "T1059"
framework = "ATTACK"
tactic = "execution"
rationale = "Composite 0.520: vector=0.480, tactic-overlap=execution"
mapping_type = "suggested"
composite_score = 0.5200

[[mappings]]
rule_id = "TH-002"
technique_id = "T1570"
framework = "ATTACK"
tactic = "lateral-movement"
rationale = "Composite 0.450: vector=0.410"
mapping_type = "suggested"
composite_score = 0.4500

[[mappings]]
rule_id = "TH-001"
technique_id = "T1203"
framework = "ATTACK"
tactic = "execution"
rationale = "Composite 0.410: vector=0.390"
mapping_type = "suggested"
composite_score = 0.4100
"""

CONFIG_TOML = """\
# Technique mapping expansion configuration.
#
# Controls how threat heuristics are expanded beyond curated mappings.

[expansion]
enabled = false
include_subtechniques = true
max_techniques_per_tactic = 20
domains = ["enterprise"]

[suggestions]
include_suggested = false
suggestions_path = "data/threat_intel/mapping_suggestions.toml"

[graphrag]
weight_vector = 0.45
weight_tactic = 0.15
weight_framework = 0.10
weight_mitigation_gap = 0.20
weight_subtechnique = 0.10
"""


@pytest.fixture()
def rules_file(tmp_path: Path) -> Path:
    path = tmp_path / "mapping_rules.toml"
    path.write_text(CURATED_TOML, encoding="utf-8")
    return path


@pytest.fixture()
def suggestions_file(tmp_path: Path) -> Path:
    path = tmp_path / "mapping_suggestions.toml"
    path.write_text(SUGGESTED_TOML, encoding="utf-8")
    return path


@pytest.fixture()
def config_file(tmp_path: Path) -> Path:
    path = tmp_path / "mapping_config.toml"
    path.write_text(CONFIG_TOML, encoding="utf-8")
    return path


# ── Curated rows ─────────────────────────────────────────────────


def test_curated_mapping_rows_returns_all(rules_file: Path) -> None:
    rows = curated_mapping_rows(rules_path=rules_file)
    assert len(rows) == 3
    assert all("rule_id" in r for r in rows)
    assert all("technique_id" in r for r in rows)


def test_curated_mapping_rows_filters_by_rule(rules_file: Path) -> None:
    rows = curated_mapping_rows("TH-001", rules_path=rules_file)
    assert len(rows) == 2
    assert all(r["rule_id"] == "TH-001" for r in rows)


def test_curated_mapping_rows_empty_when_no_file(tmp_path: Path) -> None:
    rows = curated_mapping_rows(rules_path=tmp_path / "nonexistent.toml")
    assert rows == []


# ── Suggested rows ───────────────────────────────────────────────


def test_suggested_mapping_rows_empty_when_no_file(tmp_path: Path) -> None:
    rows = suggested_mapping_rows(suggestions_path=tmp_path / "nonexistent.toml")
    assert rows == []


def test_suggested_mapping_rows_loads_entries(suggestions_file: Path) -> None:
    rows = suggested_mapping_rows(suggestions_path=suggestions_file)
    assert len(rows) == 3
    assert all(r["mapping_type"] == "suggested" for r in rows)
    assert rows[0]["composite_score"] == pytest.approx(0.52, abs=0.001)


def test_suggested_mapping_rows_filters_by_rule(suggestions_file: Path) -> None:
    rows = suggested_mapping_rows("TH-001", suggestions_path=suggestions_file)
    assert len(rows) == 2
    assert all(r["rule_id"] == "TH-001" for r in rows)


# ── Heuristics ───────────────────────────────────────────────────


def test_heuristic_rows_returns_discovered() -> None:
    rows = heuristic_rows()
    assert len(rows) >= 6
    assert all("rule_id" in r for r in rows)
    assert all("name" in r for r in rows)
    assert all("frameworks" in r for r in rows)
    assert all("severity" in r for r in rows)


# ── Mapping config ───────────────────────────────────────────────


def test_load_mapping_config(config_file: Path) -> None:
    config = load_mapping_config(config_path=config_file)
    assert "expansion" in config
    assert "suggestions" in config
    assert config["expansion"]["enabled"] is False
    assert config["suggestions"]["include_suggested"] is False


def test_load_mapping_config_missing_file(tmp_path: Path) -> None:
    config = load_mapping_config(config_path=tmp_path / "missing.toml")
    assert config["expansion"]["enabled"] is False
    assert config["suggestions"]["include_suggested"] is False


def test_save_mapping_config_roundtrip(config_file: Path) -> None:
    config = load_mapping_config(config_path=config_file)
    config["expansion"]["enabled"] = True
    config["suggestions"]["include_suggested"] = True
    config["graphrag"]["weight_vector"] = 0.5
    save_mapping_config(config, config_path=config_file)

    reloaded = load_mapping_config(config_path=config_file)
    assert reloaded["expansion"]["enabled"] is True
    assert reloaded["suggestions"]["include_suggested"] is True
    assert reloaded["graphrag"]["weight_vector"] == pytest.approx(0.5)
    # Unchanged fields preserved
    assert reloaded["expansion"]["include_subtechniques"] is True
    assert reloaded["expansion"]["max_techniques_per_tactic"] == 20


# ── Promote ──────────────────────────────────────────────────────


def test_promote_suggestion_appends_to_rules(
    rules_file: Path,
    suggestions_file: Path,
) -> None:
    ok = promote_suggestion(
        "TH-001", "T1059",
        rules_path=rules_file,
        suggestions_path=suggestions_file,
    )
    assert ok is True

    # New entry in curated
    rows = curated_mapping_rows(rules_path=rules_file)
    promoted = [r for r in rows if r["technique_id"] == "T1059"]
    assert len(promoted) == 1
    assert promoted[0]["rule_id"] == "TH-001"
    assert promoted[0]["framework"] == "ATTACK"


def test_promote_suggestion_removes_from_suggestions(
    rules_file: Path,
    suggestions_file: Path,
) -> None:
    ok = promote_suggestion(
        "TH-001", "T1059",
        rules_path=rules_file,
        suggestions_path=suggestions_file,
    )
    assert ok is True

    remaining = suggested_mapping_rows(suggestions_path=suggestions_file)
    assert len(remaining) == 2
    assert not any(r["technique_id"] == "T1059" for r in remaining)


def test_promote_nonexistent_returns_false(
    rules_file: Path,
    suggestions_file: Path,
) -> None:
    ok = promote_suggestion(
        "TH-099", "T9999",
        rules_path=rules_file,
        suggestions_path=suggestions_file,
    )
    assert ok is False


def test_promote_suggestion_preserves_toml_escaping(
    rules_file: Path,
    suggestions_file: Path,
) -> None:
    suggestions_file.write_text(
        """\
[[mappings]]
rule_id = "TH-001"
technique_id = "T1059"
framework = "ATTACK"
tactic = "execution"
rationale = "Quote: \\"x\\"\\nLine two"
mapping_type = "suggested"
composite_score = 0.5
""",
        encoding="utf-8",
    )

    ok = promote_suggestion(
        "TH-001", "T1059",
        rules_path=rules_file,
        suggestions_path=suggestions_file,
    )

    assert ok is True
    rows = curated_mapping_rows(rules_path=rules_file)
    promoted = next(r for r in rows if r["technique_id"] == "T1059")
    assert promoted["rationale"] == 'Quote: "x"\nLine two'


# ── Sync actions ─────────────────────────────────────────────────


def test_sync_knowledge_action_builds_correct_args() -> None:
    calls: list[tuple] = []

    def fake_executor(command, _cwd):
        calls.append(tuple(command))
        return ActionResult(ok=True, command=" ".join(command), returncode=0, stdout="ok", stderr="")

    sync_knowledge(
        attack_version="v16.1",
        atlas_version="4.1",
        embed=True,
        executor=fake_executor,
    )

    assert len(calls) == 1
    args = calls[0]
    assert "sync" in args
    assert "--attack-version" in args
    assert "v16.1" in args
    assert "--atlas-version" in args
    assert "4.1" in args
    assert "--embed" in args
    assert "--map-heuristics" not in args


def test_sync_knowledge_action_map_heuristics_flags() -> None:
    calls: list[tuple] = []

    def fake_executor(command, _cwd):
        calls.append(tuple(command))
        return ActionResult(ok=True, command=" ".join(command), returncode=0, stdout="ok", stderr="")

    sync_knowledge(
        map_heuristics=True,
        map_threshold=0.50,
        map_top_k=15,
        executor=fake_executor,
    )

    args = calls[0]
    assert "--embed" in args
    assert "--map-heuristics" in args
    assert "--map-threshold" in args
    assert "0.5" in args
    assert "--map-top-k" in args
    assert "15" in args


def test_get_sync_status_action() -> None:
    calls: list[tuple] = []

    def fake_executor(command, _cwd):
        calls.append(tuple(command))
        return ActionResult(ok=True, command=" ".join(command), returncode=0, stdout="synced", stderr="")

    result = get_sync_status(executor=fake_executor)
    assert result.ok is True
    args = calls[0]
    assert "sync" in args
    assert "--status" in args


# ── Sync status (in-process) ────────────────────────────────────


def test_load_sync_status_not_synced(tmp_path: Path) -> None:
    from project_paths import ProjectPaths

    paths = ProjectPaths.from_root(tmp_path)
    status = load_sync_status(paths=paths)
    assert status["status"] == "not synced"
