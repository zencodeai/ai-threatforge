from __future__ import annotations

import json

from knowledge.models import Mitigation, Tactic, Technique
from knowledge.store import TechniqueStore


def _sample_tactics() -> list[Tactic]:
    return [
        Tactic("TA0001", "Initial Access", "ATTACK", "enterprise", "initial-access", 0),
        Tactic("TA0002", "Execution", "ATTACK", "enterprise", "execution", 1),
        Tactic("TA0040", "Impact", "ATTACK", "enterprise", "impact", 12),
        Tactic("AML.TA0001", "Reconnaissance", "ATLAS", "atlas", "reconnaissance", 0),
        Tactic("AML.TA0002", "ML Attack Staging", "ATLAS", "atlas", "ml-attack-staging", 1),
    ]


def _sample_techniques() -> list[Technique]:
    return [
        Technique("T1190", "Exploit Public-Facing Application", "ATTACK", "enterprise",
                  "Adversaries may exploit vulnerabilities in internet-facing software.",
                  False, None, ("Linux", "Windows", "macOS"), ("initial-access",), False,
                  "https://attack.mitre.org/techniques/T1190"),
        Technique("T1078", "Valid Accounts", "ATTACK", "enterprise",
                  "Adversaries may use valid accounts to maintain access.",
                  False, None, ("Linux", "Windows", "macOS"), ("initial-access", "defense-evasion"), False,
                  "https://attack.mitre.org/techniques/T1078"),
        Technique("T1078.001", "Valid Accounts: Default Accounts", "ATTACK", "enterprise",
                  "Adversaries may use default accounts.",
                  True, "T1078", ("Linux", "Windows"), ("initial-access",), False,
                  "https://attack.mitre.org/techniques/T1078/001"),
        Technique("T1059", "Command and Scripting Interpreter", "ATTACK", "enterprise",
                  "Adversaries may abuse command and script interpreters.",
                  False, None, ("Linux", "Windows", "macOS"), ("execution",), False,
                  "https://attack.mitre.org/techniques/T1059"),
        Technique("T1499", "Endpoint Denial of Service", "ATTACK", "enterprise",
                  "Adversaries may perform DoS targeting endpoint availability.",
                  False, None, ("Linux", "Windows"), ("impact",), False,
                  "https://attack.mitre.org/techniques/T1499"),
        Technique("T9999", "Deprecated Technique", "ATTACK", "enterprise",
                  "This technique is deprecated.",
                  False, None, (), (), True, ""),
        Technique("AML.T0016", "Data Poisoning", "ATLAS", "atlas",
                  "Adversaries may poison training data.",
                  False, None, (), ("ml-attack-staging",), False,
                  "https://atlas.mitre.org/techniques/AML.T0016"),
        Technique("AML.T0040", "Model Evasion", "ATLAS", "atlas",
                  "Adversaries may craft inputs to evade model detection.",
                  False, None, (), ("ml-attack-staging",), False,
                  "https://atlas.mitre.org/techniques/AML.T0040"),
    ]


def _sample_mitigations() -> list[Mitigation]:
    return [
        Mitigation("M1036", "Account Use Policies", "ATTACK", "enterprise",
                   "Configure account use policies.", ("T1078",)),
        Mitigation("M1050", "Exploit Protection", "ATTACK", "enterprise",
                   "Use exploit protection.", ("T1190", "T1499")),
        Mitigation("AML.M0001", "Curate Training Data", "ATLAS", "atlas",
                   "Curate and validate training data.", ("AML.T0016",)),
    ]


def _populated_store(tmp_path) -> TechniqueStore:
    db_path = tmp_path / "test_kb.db"
    store = TechniqueStore(db_path)
    store.replace_all(
        tactics=_sample_tactics(),
        techniques=_sample_techniques(),
        mitigations=_sample_mitigations(),
    )
    store.set_meta("attack_version", "18.1")
    store.set_meta("atlas_version", "5.5.0")
    return store


# ── TechniqueStore tests ──────────────────────────────────────────


def test_store_schema_creation(tmp_path):
    db_path = tmp_path / "empty.db"
    store = TechniqueStore(db_path)
    assert not store.is_populated()
    assert store.technique_count() == 0
    store.close()


def test_store_replace_all_and_counts(tmp_path):
    store = _populated_store(tmp_path)
    assert store.is_populated()
    assert store.technique_count() == 8  # includes deprecated
    store.close()


def test_store_load_all_techniques(tmp_path):
    store = _populated_store(tmp_path)
    techniques = store.load_all_techniques()
    ids = {t.technique_id for t in techniques}
    assert "T1190" in ids
    assert "AML.T0016" in ids
    # Check sub-technique
    sub = next(t for t in techniques if t.technique_id == "T1078.001")
    assert sub.is_subtechnique is True
    assert sub.parent_id == "T1078"
    store.close()


def test_store_load_all_tactics(tmp_path):
    store = _populated_store(tmp_path)
    tactics = store.load_all_tactics()
    assert len(tactics) >= 3
    assert tactics[0].order <= tactics[1].order
    store.close()


def test_store_load_all_mitigations(tmp_path):
    store = _populated_store(tmp_path)
    mitigations = store.load_all_mitigations()
    assert len(mitigations) == 3
    m1036 = next(m for m in mitigations if m.mitigation_id == "M1036")
    assert "T1078" in m1036.technique_ids
    store.close()


def test_store_meta_roundtrip(tmp_path):
    store = _populated_store(tmp_path)
    assert store.get_meta("attack_version") == "18.1"
    assert store.get_meta("missing_key", "default") == "default"
    store.close()


def test_store_replace_is_idempotent(tmp_path):
    store = _populated_store(tmp_path)
    count1 = store.technique_count()
    store.replace_all(
        tactics=_sample_tactics(),
        techniques=_sample_techniques(),
        mitigations=_sample_mitigations(),
    )
    assert store.technique_count() == count1
    store.close()


def test_store_tactic_shortname_linking(tmp_path):
    store = _populated_store(tmp_path)
    techniques = store.load_all_techniques()
    t1190 = next(t for t in techniques if t.technique_id == "T1190")
    assert "initial-access" in t1190.tactics
    store.close()
