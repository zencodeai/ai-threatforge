from __future__ import annotations

from knowledge.sync_attack import parse_attack_bundle
from knowledge.sync_atlas import parse_atlas_data
from knowledge.sync import _dedup_tactics, _dedup_techniques, _dedup_mitigations
from knowledge.models import Mitigation, Tactic, Technique


# ── ATT&CK STIX parsing tests ────────────────────────────────────


def _minimal_attack_bundle() -> dict:
    """A minimal valid STIX bundle with representative ATT&CK objects."""
    return {
        "type": "bundle",
        "id": "bundle--test",
        "objects": [
            {
                "type": "x-mitre-matrix",
                "id": "x-mitre-matrix--test",
                "name": "Enterprise ATT&CK",
                "tactic_refs": ["x-mitre-tactic--ta0001", "x-mitre-tactic--ta0002"],
            },
            {
                "type": "x-mitre-tactic",
                "id": "x-mitre-tactic--ta0001",
                "name": "Initial Access",
                "x_mitre_shortname": "initial-access",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "TA0001"}
                ],
            },
            {
                "type": "x-mitre-tactic",
                "id": "x-mitre-tactic--ta0002",
                "name": "Execution",
                "x_mitre_shortname": "execution",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "TA0002"}
                ],
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--t1190",
                "name": "Exploit Public-Facing Application",
                "description": "Adversaries may exploit vulnerabilities.",
                "x_mitre_platforms": ["Linux", "Windows"],
                "x_mitre_is_subtechnique": False,
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}
                ],
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": "T1190",
                        "url": "https://attack.mitre.org/techniques/T1190",
                    }
                ],
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--t1059",
                "name": "Command and Scripting Interpreter",
                "description": "Adversaries may abuse interpreters.",
                "x_mitre_platforms": ["Linux", "Windows", "macOS"],
                "x_mitre_is_subtechnique": False,
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": "execution"}
                ],
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": "T1059",
                        "url": "https://attack.mitre.org/techniques/T1059",
                    }
                ],
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--t1059-001",
                "name": "PowerShell",
                "description": "Adversaries may use PowerShell.",
                "x_mitre_platforms": ["Windows"],
                "x_mitre_is_subtechnique": True,
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": "execution"}
                ],
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": "T1059.001",
                        "url": "https://attack.mitre.org/techniques/T1059/001",
                    }
                ],
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--deprecated",
                "name": "Old Technique",
                "description": "Deprecated.",
                "x_mitre_deprecated": True,
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T9998"}
                ],
            },
            {
                "type": "relationship",
                "id": "relationship--sub",
                "relationship_type": "subtechnique-of",
                "source_ref": "attack-pattern--t1059-001",
                "target_ref": "attack-pattern--t1059",
            },
            {
                "type": "course-of-action",
                "id": "course-of-action--m1050",
                "name": "Exploit Protection",
                "description": "Use exploit protection.",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "M1050"}
                ],
            },
            {
                "type": "relationship",
                "id": "relationship--mitigates",
                "relationship_type": "mitigates",
                "source_ref": "course-of-action--m1050",
                "target_ref": "attack-pattern--t1190",
            },
        ],
    }


def test_parse_attack_bundle_extracts_tactics():
    tactics, _, _ = parse_attack_bundle(_minimal_attack_bundle(), "enterprise-attack")
    ids = {t.tactic_id for t in tactics}
    assert "TA0001" in ids
    assert "TA0002" in ids
    # Check ordering
    ta0001 = next(t for t in tactics if t.tactic_id == "TA0001")
    ta0002 = next(t for t in tactics if t.tactic_id == "TA0002")
    assert ta0001.order < ta0002.order


def test_parse_attack_bundle_extracts_techniques():
    _, techniques, _ = parse_attack_bundle(_minimal_attack_bundle(), "enterprise-attack")
    ids = {t.technique_id for t in techniques}
    assert "T1190" in ids
    assert "T1059" in ids
    assert "T1059.001" in ids
    assert "T9998" in ids  # deprecated but still extracted (flagged)

    t1190 = next(t for t in techniques if t.technique_id == "T1190")
    assert t1190.framework == "ATTACK"
    assert t1190.domain == "enterprise"
    assert "Linux" in t1190.platforms
    assert "initial-access" in t1190.tactics
    assert not t1190.deprecated


def test_parse_attack_bundle_subtechnique_parent():
    _, techniques, _ = parse_attack_bundle(_minimal_attack_bundle(), "enterprise-attack")
    sub = next(t for t in techniques if t.technique_id == "T1059.001")
    assert sub.is_subtechnique is True
    assert sub.parent_id == "T1059"


def test_parse_attack_bundle_deprecated_flag():
    _, techniques, _ = parse_attack_bundle(_minimal_attack_bundle(), "enterprise-attack")
    dep = next(t for t in techniques if t.technique_id == "T9998")
    assert dep.deprecated is True


def test_parse_attack_bundle_mitigations():
    _, _, mitigations = parse_attack_bundle(_minimal_attack_bundle(), "enterprise-attack")
    assert len(mitigations) == 1
    m = mitigations[0]
    assert m.mitigation_id == "M1050"
    assert "T1190" in m.technique_ids


def test_parse_attack_bundle_framework_and_domain():
    tactics, techniques, mitigations = parse_attack_bundle(_minimal_attack_bundle(), "enterprise-attack")
    for t in tactics:
        assert t.framework == "ATTACK"
        assert t.domain == "enterprise"
    for t in techniques:
        assert t.framework == "ATTACK"
        assert t.domain == "enterprise"


# ── ATLAS YAML parsing tests ─────────────────────────────────────


def _minimal_atlas_data() -> dict:
    return {
        "id": "ATLAS",
        "name": "ATLAS",
        "version": "5.5.0",
        "matrices": [
            {
                "id": "ATLAS",
                "name": "ATLAS Matrix",
                "tactics": [
                    {"id": "AML.TA0001", "name": "Reconnaissance", "shortname": "reconnaissance"},
                    {"id": "AML.TA0002", "name": "ML Attack Staging", "shortname": "ml-attack-staging"},
                ],
                "techniques": [
                    {
                        "id": "AML.T0016",
                        "name": "Data Poisoning",
                        "description": "Adversaries may poison training data.",
                        "tactics": ["AML.TA0002"],
                    },
                    {
                        "id": "AML.T0040",
                        "name": "Model Evasion",
                        "description": "Adversaries may evade model detection.",
                        "tactics": ["AML.TA0002"],
                    },
                    {
                        "id": "AML.T0016.001",
                        "name": "Data Poisoning: Label Corruption",
                        "description": "Corrupt labels.",
                        "tactics": ["AML.TA0002"],
                        "subtechnique-of": "AML.T0016",
                    },
                ],
                "mitigations": [
                    {
                        "id": "AML.M0001",
                        "name": "Curate Training Data",
                        "description": "Curate training data.",
                        "techniques": ["AML.T0016"],
                    },
                ],
            }
        ],
    }


def test_parse_atlas_tactics():
    tactics, _, _ = parse_atlas_data(_minimal_atlas_data())
    assert len(tactics) == 2
    assert tactics[0].tactic_id == "AML.TA0001"
    assert tactics[0].framework == "ATLAS"
    assert tactics[0].domain == "atlas"


def test_parse_atlas_techniques():
    _, techniques, _ = parse_atlas_data(_minimal_atlas_data())
    ids = {t.technique_id for t in techniques}
    assert "AML.T0016" in ids
    assert "AML.T0040" in ids
    assert "AML.T0016.001" in ids

    t0016 = next(t for t in techniques if t.technique_id == "AML.T0016")
    assert t0016.framework == "ATLAS"
    assert not t0016.is_subtechnique
    assert t0016.parent_id is None


def test_parse_atlas_subtechnique():
    _, techniques, _ = parse_atlas_data(_minimal_atlas_data())
    sub = next(t for t in techniques if t.technique_id == "AML.T0016.001")
    assert sub.is_subtechnique is True
    assert sub.parent_id == "AML.T0016"


def test_parse_atlas_mitigations():
    _, _, mitigations = parse_atlas_data(_minimal_atlas_data())
    assert len(mitigations) == 1
    assert mitigations[0].mitigation_id == "AML.M0001"
    assert "AML.T0016" in mitigations[0].technique_ids


def test_parse_atlas_tactic_shortnames():
    _, techniques, _ = parse_atlas_data(_minimal_atlas_data())
    t0016 = next(t for t in techniques if t.technique_id == "AML.T0016")
    assert "ml-attack-staging" in t0016.tactics


def test_parse_atlas_empty_matrices():
    tactics, techniques, mitigations = parse_atlas_data({"matrices": []})
    assert tactics == []
    assert techniques == []
    assert mitigations == []


# ── Cross-domain dedup tests ─────────────────────────────────────


def test_dedup_tactics_keeps_first():
    t1 = Tactic("TA0001", "Initial Access", "ATTACK", "enterprise", "initial-access", 0)
    t2 = Tactic("TA0001", "Initial Access", "ATTACK", "mobile", "initial-access", 0)
    result = _dedup_tactics([t1, t2])
    assert len(result) == 1
    assert result[0].domain == "enterprise"


def test_dedup_techniques_merges_platforms_and_tactics():
    t1 = Technique("T1190", "Exploit", "ATTACK", "enterprise", "desc", False, None,
                    ("Linux", "Windows"), ("initial-access",), False, "")
    t2 = Technique("T1190", "Exploit", "ATTACK", "mobile", "desc", False, None,
                    ("Android",), ("initial-access", "execution"), False, "")
    result = _dedup_techniques([t1, t2])
    assert len(result) == 1
    assert set(result[0].platforms) == {"Linux", "Windows", "Android"}
    assert set(result[0].tactics) == {"initial-access", "execution"}


def test_dedup_mitigations_merges_technique_ids():
    m1 = Mitigation("M1050", "Exploit Protection", "ATTACK", "enterprise", "desc", ("T1190",))
    m2 = Mitigation("M1050", "Exploit Protection", "ATTACK", "mobile", "desc", ("T1190", "T1404"))
    result = _dedup_mitigations([m1, m2])
    assert len(result) == 1
    assert set(result[0].technique_ids) == {"T1190", "T1404"}


def test_parse_atlas_handles_dict_typed_tactics_and_techniques():
    """Real ATLAS YAML uses dicts for tactic refs and mitigation technique refs."""
    data = {
        "matrices": [{
            "id": "ATLAS",
            "name": "ATLAS Matrix",
            "tactics": [
                {"id": "AML.TA0002", "name": "ML Attack Staging", "shortname": "ml-attack-staging"},
            ],
            "techniques": [
                {
                    "id": "AML.T0016",
                    "name": "Data Poisoning",
                    "description": "desc",
                    "tactics": [{"id": "AML.TA0002", "name": "ML Attack Staging"}],
                },
            ],
            "mitigations": [
                {
                    "id": "AML.M0001",
                    "name": "Curate Training Data",
                    "description": "desc",
                    "techniques": [{"id": "AML.T0016", "name": "Data Poisoning"}],
                },
            ],
        }],
    }
    tactics, techniques, mitigations = parse_atlas_data(data)
    assert techniques[0].tactics == ("ml-attack-staging",)
    assert mitigations[0].technique_ids == ("AML.T0016",)
