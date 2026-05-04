"""Tests for the KnowledgeGraphLoader — MITRE knowledge graph loading into Neo4j."""

from __future__ import annotations

from pathlib import Path

import pytest

from graph.knowledge_loader import KnowledgeGraphLoader, KnowledgeLoadStats
from knowledge.models import Mitigation, Tactic, Technique


# ── Fake Neo4j client ───────────────────────────────────────────


class FakeClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict | None]] = []

    def execute_write(self, query: str, parameters: dict | None = None) -> None:
        self.calls.append((query.strip(), parameters))

    def run_query(self, query: str, parameters: dict | None = None) -> list[dict]:
        self.calls.append((query.strip(), parameters))
        return [{"edge_count": 2}]


# ── Sample MITRE data ──────────────────────────────────────────


def _sample_tactics() -> list[Tactic]:
    return [
        Tactic(
            tactic_id="TA0001",
            name="Initial Access",
            framework="ATTACK",
            domain="enterprise",
            shortname="initial-access",
            order=1,
        ),
        Tactic(
            tactic_id="TA0040",
            name="Reconnaissance",
            framework="ATTACK",
            domain="enterprise",
            shortname="reconnaissance",
            order=0,
        ),
    ]


def _sample_techniques() -> list[Technique]:
    return [
        Technique(
            technique_id="T1190",
            name="Exploit Public-Facing Application",
            framework="ATTACK",
            domain="enterprise",
            description="Adversaries may attempt to exploit...",
            is_subtechnique=False,
            parent_id=None,
            platforms=("Linux", "Windows"),
            tactics=("initial-access",),
            deprecated=False,
            url="https://attack.mitre.org/techniques/T1190",
        ),
        Technique(
            technique_id="T1190.001",
            name="Exploit via Web Application",
            framework="ATTACK",
            domain="enterprise",
            description="A sub-technique of T1190...",
            is_subtechnique=True,
            parent_id="T1190",
            platforms=("Linux",),
            tactics=("initial-access",),
            deprecated=False,
            url="https://attack.mitre.org/techniques/T1190/001",
        ),
        Technique(
            technique_id="T1078",
            name="Valid Accounts",
            framework="ATTACK",
            domain="enterprise",
            description="Adversaries may obtain and abuse...",
            is_subtechnique=False,
            parent_id=None,
            platforms=("Linux", "Windows", "macOS"),
            tactics=("initial-access", "reconnaissance"),
            deprecated=False,
            url="https://attack.mitre.org/techniques/T1078",
        ),
    ]


def _sample_mitigations() -> list[Mitigation]:
    return [
        Mitigation(
            mitigation_id="M1050",
            name="Exploit Protection",
            framework="ATTACK",
            domain="enterprise",
            description="Use exploit protection features...",
            technique_ids=("T1190", "T1190.001"),
        ),
        Mitigation(
            mitigation_id="M1036",
            name="Account Use Policies",
            framework="ATTACK",
            domain="enterprise",
            description="Configure features related to account use...",
            technique_ids=("T1078",),
        ),
    ]


# ── Schema tests ────────────────────────────────────────────────


class TestKnowledgeGraphLoaderSchema:

    def test_apply_schema_reads_mitre_constraint_files(self) -> None:
        fake = FakeClient()
        loader = KnowledgeGraphLoader(fake)  # type: ignore[arg-type]
        root = Path(__file__).resolve().parents[1] / "src" / "graph"
        loader.apply_schema(root)

        queries = [q for q, _ in fake.calls]
        assert any("technique_id_unique" in q for q in queries)
        assert any("tactic_id_unique" in q for q in queries)
        assert any("mitigation_id_unique" in q for q in queries)
        assert any("heuristic_rule_id_unique" in q for q in queries)
        assert any("technique_framework_idx" in q for q in queries)
        assert any("tactic_shortname_idx" in q for q in queries)


# ── MITRE node merge tests ──────────────────────────────────────


class TestMITRENodeMerge:

    def test_merge_tactics(self) -> None:
        fake = FakeClient()
        loader = KnowledgeGraphLoader(fake)  # type: ignore[arg-type]
        stats = loader.load_mitre_data(
            tactics=_sample_tactics(),
            techniques=[],
            mitigations=[],
        )
        assert stats.tactics == 2
        queries = [q for q, _ in fake.calls]
        assert any("MERGE (t:Tactic {tactic_id: row.tactic_id})" in q for q in queries)

    def test_merge_techniques(self) -> None:
        fake = FakeClient()
        loader = KnowledgeGraphLoader(fake)  # type: ignore[arg-type]
        stats = loader.load_mitre_data(
            tactics=_sample_tactics(),
            techniques=_sample_techniques(),
            mitigations=[],
        )
        assert stats.techniques == 3

        queries = [q for q, _ in fake.calls]
        assert any("MERGE (t:Technique {technique_id: row.technique_id})" in q for q in queries)

    def test_merge_mitigations(self) -> None:
        fake = FakeClient()
        loader = KnowledgeGraphLoader(fake)  # type: ignore[arg-type]
        stats = loader.load_mitre_data(
            tactics=_sample_tactics(),
            techniques=_sample_techniques(),
            mitigations=_sample_mitigations(),
        )
        assert stats.mitigations == 2
        queries = [q for q, _ in fake.calls]
        assert any("MERGE (m:Mitigation {mitigation_id: row.mitigation_id})" in q for q in queries)

    def test_empty_data_produces_zero_stats(self) -> None:
        fake = FakeClient()
        loader = KnowledgeGraphLoader(fake)  # type: ignore[arg-type]
        stats = loader.load_mitre_data(tactics=[], techniques=[], mitigations=[])
        assert stats.tactics == 0
        assert stats.techniques == 0
        assert stats.mitigations == 0


# ── Relationship tests ──────────────────────────────────────────


class TestMITRERelationships:

    def test_technique_tactic_links(self) -> None:
        fake = FakeClient()
        loader = KnowledgeGraphLoader(fake)  # type: ignore[arg-type]
        loader.load_mitre_data(
            tactics=_sample_tactics(),
            techniques=_sample_techniques(),
            mitigations=[],
        )
        queries = [q for q, _ in fake.calls]
        assert any("MERGE (tech)-[:IN_TACTIC]->(tac)" in q for q in queries)

    def test_subtechnique_links(self) -> None:
        fake = FakeClient()
        loader = KnowledgeGraphLoader(fake)  # type: ignore[arg-type]
        loader.load_mitre_data(
            tactics=_sample_tactics(),
            techniques=_sample_techniques(),
            mitigations=[],
        )
        # Verify subtechnique batch data
        sub_calls = [
            (q, p) for q, p in fake.calls
            if "IS_SUBTECHNIQUE_OF" in q and p and "batch" in p
        ]
        assert sub_calls
        batch = sub_calls[0][1]["batch"]
        assert len(batch) == 1
        assert batch[0]["technique_id"] == "T1190.001"
        assert batch[0]["parent_id"] == "T1190"

    def test_technique_mitigation_links(self) -> None:
        fake = FakeClient()
        loader = KnowledgeGraphLoader(fake)  # type: ignore[arg-type]
        loader.load_mitre_data(
            tactics=_sample_tactics(),
            techniques=_sample_techniques(),
            mitigations=_sample_mitigations(),
        )
        queries = [q for q, _ in fake.calls]
        assert any("MERGE (tech)-[:MITIGATED_BY]->(mit)" in q for q in queries)

        # M1050 mitigates T1190 and T1190.001 → 2 edges
        # M1036 mitigates T1078 → 1 edge
        mit_calls = [
            (q, p) for q, p in fake.calls
            if "MITIGATED_BY" in q and p and "batch" in p
        ]
        assert mit_calls
        batch = mit_calls[0][1]["batch"]
        assert len(batch) == 3

    def test_technique_batch_data_contents(self) -> None:
        fake = FakeClient()
        loader = KnowledgeGraphLoader(fake)  # type: ignore[arg-type]
        loader.load_mitre_data(
            tactics=_sample_tactics(),
            techniques=_sample_techniques(),
            mitigations=[],
        )
        tech_calls = [
            (q, p) for q, p in fake.calls
            if "MERGE (t:Technique" in q and p and "batch" in p
        ]
        assert tech_calls
        batch = tech_calls[0][1]["batch"]
        t1190 = next(t for t in batch if t["technique_id"] == "T1190")
        assert t1190["name"] == "Exploit Public-Facing Application"
        assert t1190["framework"] == "ATTACK"
        assert t1190["is_subtechnique"] is False
        assert "Linux" in t1190["platforms"]


# ── Bridge tests ────────────────────────────────────────────────


class TestHeuristicBridges:

    def test_heuristic_rule_nodes_created(self) -> None:
        fake = FakeClient()
        loader = KnowledgeGraphLoader(fake)  # type: ignore[arg-type]

        rules = [
            {"rule_id": "TH-001", "name": "Test Rule", "severity_hint": "high", "target_type": "module"},
        ]
        mappings = [
            {"rule_id": "TH-001", "technique_id": "T1190", "tactic": "initial-access", "rationale": "Test"},
        ]
        rule_count, map_count = loader.load_heuristic_bridges(
            heuristic_rules=rules,
            curated_mappings=mappings,
        )
        assert rule_count == 1
        assert map_count == 1

        queries = [q for q, _ in fake.calls]
        assert any("MERGE (h:HeuristicRule {rule_id: row.rule_id})" in q for q in queries)
        assert any("MERGE (h)-[r:MAPS_TO {tactic: row.tactic}]->(t)" in q for q in queries)

    def test_maps_to_edge_properties(self) -> None:
        fake = FakeClient()
        loader = KnowledgeGraphLoader(fake)  # type: ignore[arg-type]

        rules = [
            {"rule_id": "TH-001", "name": "Test", "severity_hint": "high", "target_type": "module"},
        ]
        mappings = [
            {
                "rule_id": "TH-001",
                "technique_id": "T1190",
                "tactic": "initial-access",
                "rationale": "Exposed services are targets",
            },
        ]
        loader.load_heuristic_bridges(heuristic_rules=rules, curated_mappings=mappings)

        map_calls = [
            (q, p) for q, p in fake.calls
            if "MAPS_TO" in q and p and "batch" in p
        ]
        assert map_calls
        batch = map_calls[0][1]["batch"]
        assert batch[0]["mapping_type"] == "curated"
        assert batch[0]["rationale"] == "Exposed services are targets"

    def test_empty_rules_returns_zeros(self) -> None:
        fake = FakeClient()
        loader = KnowledgeGraphLoader(fake)  # type: ignore[arg-type]
        rule_count, map_count = loader.load_heuristic_bridges(
            heuristic_rules=[],
            curated_mappings=[],
        )
        assert rule_count == 0
        assert map_count == 0

    def test_rules_without_mappings(self) -> None:
        fake = FakeClient()
        loader = KnowledgeGraphLoader(fake)  # type: ignore[arg-type]
        rules = [
            {"rule_id": "TH-099", "name": "Unmapped Rule", "severity_hint": "low", "target_type": "module"},
        ]
        rule_count, map_count = loader.load_heuristic_bridges(
            heuristic_rules=rules,
            curated_mappings=[],
        )
        assert rule_count == 1
        assert map_count == 0


class TestControlBridges:

    def test_sync_control_bridges_runs_cypher(self) -> None:
        fake = FakeClient()
        loader = KnowledgeGraphLoader(fake)  # type: ignore[arg-type]
        count = loader.sync_control_bridges()
        assert count == 2  # FakeClient returns edge_count=2

        queries = [q for q, _ in fake.calls]
        assert any("IMPLEMENTS_CONTROL" in q for q in queries)
        assert any("m.control_functions" in q for q in queries)


# ── Full pipeline test ──────────────────────────────────────────


class TestFullPipeline:

    def test_load_mitre_then_bridges(self) -> None:
        """Verify full Phase A flow: MITRE data + heuristic bridges + control bridges."""
        fake = FakeClient()
        loader = KnowledgeGraphLoader(fake)  # type: ignore[arg-type]

        stats = loader.load_mitre_data(
            tactics=_sample_tactics(),
            techniques=_sample_techniques(),
            mitigations=_sample_mitigations(),
        )
        assert stats.tactics == 2
        assert stats.techniques == 3
        assert stats.mitigations == 2

        rules = [
            {"rule_id": "TH-001", "name": "Internet-exposed module", "severity_hint": "high", "target_type": "module"},
            {"rule_id": "TH-002", "name": "Cross-trust attack path", "severity_hint": "high", "target_type": "module"},
        ]
        mappings = [
            {"rule_id": "TH-001", "technique_id": "T1190", "tactic": "initial-access", "rationale": "Exposed"},
            {"rule_id": "TH-001", "technique_id": "T1078", "tactic": "initial-access", "rationale": "Valid accounts"},
            {"rule_id": "TH-002", "technique_id": "T1078", "tactic": "initial-access", "rationale": "Lateral"},
        ]
        rule_count, map_count = loader.load_heuristic_bridges(
            heuristic_rules=rules,
            curated_mappings=mappings,
        )
        assert rule_count == 2
        assert map_count == 3

        ctrl_count = loader.sync_control_bridges()
        assert ctrl_count == 2

    def test_idempotent_merge(self) -> None:
        """Running load_mitre_data twice should use MERGE (no duplicates)."""
        fake = FakeClient()
        loader = KnowledgeGraphLoader(fake)  # type: ignore[arg-type]
        tactics = _sample_tactics()
        techniques = _sample_techniques()
        mitigations = _sample_mitigations()

        stats1 = loader.load_mitre_data(
            tactics=tactics, techniques=techniques, mitigations=mitigations,
        )
        call_count_1 = len(fake.calls)

        stats2 = loader.load_mitre_data(
            tactics=tactics, techniques=techniques, mitigations=mitigations,
        )
        call_count_2 = len(fake.calls) - call_count_1

        # Same number of Cypher calls (MERGE is idempotent)
        assert call_count_1 == call_count_2
        assert stats1.techniques == stats2.techniques
