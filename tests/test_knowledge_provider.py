from __future__ import annotations

from pathlib import Path

from knowledge.models import Mitigation, Tactic, Technique
from knowledge.provider import KnowledgeProvider
from knowledge.store import TechniqueStore


def _seed_store(db_path: Path, *, technique_name: str, last_sync_utc: str) -> None:
    with TechniqueStore(db_path) as store:
        store.replace_all(
            tactics=[Tactic("TA0001", "Initial Access", "ATTACK", "enterprise", "initial-access", 0)],
            techniques=[
                Technique(
                    "T1190",
                    technique_name,
                    "ATTACK",
                    "enterprise",
                    "desc",
                    False,
                    None,
                    ("Linux",),
                    ("initial-access",),
                    False,
                    "https://attack.mitre.org/techniques/T1190",
                )
            ],
            mitigations=[Mitigation("M1050", "Exploit Protection", "ATTACK", "enterprise", "desc", ("T1190",))],
        )
        store.set_meta("last_sync_utc", last_sync_utc)
        store.set_meta("technique_count", "1")


def test_knowledge_provider_refreshes_index_when_store_version_changes(tmp_path: Path) -> None:
    db_path = tmp_path / "kb.db"
    _seed_store(db_path, technique_name="Exploit Public-Facing Application", last_sync_utc="2026-01-01T00:00:00+00:00")

    provider = KnowledgeProvider(db_path)
    first = provider.get_index()
    assert first.lookup("T1190").name == "Exploit Public-Facing Application"

    _seed_store(db_path, technique_name="Updated Technique Name", last_sync_utc="2026-01-02T00:00:00+00:00")

    second = provider.get_index()
    assert second.lookup("T1190").name == "Updated Technique Name"
