from __future__ import annotations

from knowledge.index import TechniqueIndex
from knowledge.models import Mitigation, Tactic, Technique
from knowledge.store import TechniqueStore


def _sample_tactics() -> list[Tactic]:
    return [
        Tactic("TA0001", "Initial Access", "ATTACK", "enterprise", "initial-access", 0),
        Tactic("TA0002", "Execution", "ATTACK", "enterprise", "execution", 1),
        Tactic("TA0040", "Impact", "ATTACK", "enterprise", "impact", 12),
        Tactic("AML.TA0002", "ML Attack Staging", "ATLAS", "atlas", "ml-attack-staging", 1),
    ]


def _sample_techniques() -> list[Technique]:
    return [
        Technique("T1190", "Exploit Public-Facing Application", "ATTACK", "enterprise",
                  "Adversaries may exploit vulnerabilities in internet-facing software.",
                  False, None, ("Linux", "Windows", "macOS"), ("initial-access",), False,
                  "https://attack.mitre.org/techniques/T1190"),
        Technique("T1078", "Valid Accounts", "ATTACK", "enterprise",
                  "Adversaries may use valid accounts.",
                  False, None, ("Linux", "Windows", "macOS"), ("initial-access",), False,
                  "https://attack.mitre.org/techniques/T1078"),
        Technique("T1059", "Command and Scripting Interpreter", "ATTACK", "enterprise",
                  "Adversaries may abuse command interpreters.",
                  False, None, ("Linux", "Windows", "macOS"), ("execution",), False,
                  "https://attack.mitre.org/techniques/T1059"),
        Technique("T9999", "Deprecated Technique", "ATTACK", "enterprise",
                  "This is deprecated.", False, None, (), (), True, ""),
        Technique("AML.T0016", "Data Poisoning", "ATLAS", "atlas",
                  "Adversaries may poison training data.",
                  False, None, (), ("ml-attack-staging",), False,
                  "https://atlas.mitre.org/techniques/AML.T0016"),
    ]


def _sample_mitigations() -> list[Mitigation]:
    return [
        Mitigation("M1050", "Exploit Protection", "ATTACK", "enterprise",
                   "Use exploit protection.", ("T1190",)),
    ]


def _build_index(tmp_path) -> TechniqueIndex:
    TechniqueIndex.reset()
    db_path = tmp_path / "test_index.db"
    store = TechniqueStore(db_path)
    store.replace_all(
        tactics=_sample_tactics(),
        techniques=_sample_techniques(),
        mitigations=_sample_mitigations(),
    )
    store.set_meta("attack_version", "18.1")
    index = TechniqueIndex(store)
    store.close()
    return index


def test_index_lookup_by_id(tmp_path):
    index = _build_index(tmp_path)
    tech = index.lookup("T1190")
    assert tech is not None
    assert tech.name == "Exploit Public-Facing Application"


def test_index_lookup_case_insensitive(tmp_path):
    index = _build_index(tmp_path)
    tech = index.lookup("t1190")
    # Falls back to case-sensitive, then case-insensitive
    # Our by_id uses original case, so t1190 won't match T1190 via .upper()
    # The lookup tries upper first
    assert tech is not None


def test_index_lookup_missing(tmp_path):
    index = _build_index(tmp_path)
    assert index.lookup("T9999_NONEXISTENT") is None


def test_index_techniques_for_tactic(tmp_path):
    index = _build_index(tmp_path)
    techs = index.techniques_for_tactic("initial-access")
    ids = {t.technique_id for t in techs}
    assert "T1190" in ids
    assert "T1078" in ids
    # Deprecated technique should not appear
    assert "T9999" not in ids


def test_index_techniques_for_platform(tmp_path):
    index = _build_index(tmp_path)
    techs = index.techniques_for_platform("Linux")
    ids = {t.technique_id for t in techs}
    assert "T1190" in ids


def test_index_by_framework(tmp_path):
    index = _build_index(tmp_path)
    attack = index.by_framework.get("ATTACK", [])
    atlas = index.by_framework.get("ATLAS", [])
    assert len(attack) >= 3  # T1190, T1078, T1059 (T9999 is deprecated, excluded)
    assert len(atlas) >= 1  # AML.T0016


def test_index_mitigations_for(tmp_path):
    index = _build_index(tmp_path)
    mits = index.mitigations_for("T1190")
    assert len(mits) == 1
    assert mits[0].mitigation_id == "M1050"


def test_index_search(tmp_path):
    index = _build_index(tmp_path)
    results = index.search("exploit vulnerabilities internet")
    assert len(results) > 0
    assert results[0].technique_id == "T1190"


def test_index_search_empty_query(tmp_path):
    index = _build_index(tmp_path)
    results = index.search("")
    assert results == []


def test_index_excludes_deprecated_from_tactic(tmp_path):
    index = _build_index(tmp_path)
    all_in_framework = index.by_framework.get("ATTACK", [])
    ids = {t.technique_id for t in all_in_framework}
    assert "T9999" not in ids


def test_index_is_populated(tmp_path):
    index = _build_index(tmp_path)
    assert index.is_populated()
    assert index.technique_count == 5  # all including deprecated in by_id


def test_index_version(tmp_path):
    index = _build_index(tmp_path)
    assert index.version == "18.1"


def test_index_singleton_reset(tmp_path):
    TechniqueIndex.reset()
    assert TechniqueIndex._instance is None
