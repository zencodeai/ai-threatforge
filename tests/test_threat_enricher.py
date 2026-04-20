"""Tests for ThreatEnricher — GraphRAG-based threat enrichment."""

from __future__ import annotations

import pytest

from analysis.threat_enricher import ThreatEnricher
from models.schema.threat_model import (
    RelatedTechnique,
    SuggestedMitigation,
    TechniqueReference,
    ThreatRecord,
)


# ── Fake Neo4j client ────���────────────────────────────────────────


class FakeEnrichClient:
    """Fake client returning predetermined mitigation and relationship data."""

    def __init__(
        self,
        mitigation_rows: list[dict] | None = None,
        shared_rows: list[dict] | None = None,
        hierarchy_rows: list[dict] | None = None,
    ) -> None:
        self.calls: list[tuple[str, dict | None]] = []
        self._mitigation_rows = mitigation_rows or []
        self._shared_rows = shared_rows or []
        self._hierarchy_rows = hierarchy_rows or []

    def run_query(self, query: str, parameters: dict | None = None) -> list[dict]:
        self.calls.append((query.strip(), parameters))
        if "MITIGATED_BY]->(mit:Mitigation)" in query and "related" not in query.lower():
            return self._mitigation_rows
        if "shared_count" in query:
            return self._shared_rows
        if "IS_SUBTECHNIQUE_OF" in query:
            return self._hierarchy_rows
        return []


# ── Fake canonical model ────────────���─────────────────────────────


class FakeModule:
    def __init__(self, id: str, control_functions: list[str] | None = None) -> None:
        self.id = id
        self.control_functions = control_functions or []


class FakeModel:
    def __init__(self, modules: list[FakeModule] | None = None) -> None:
        self.modules = modules or []


# ── Helpers ─────────��─────────────────────────────────────────────


def _make_threat(
    rule_id: str = "TH-001",
    target_id: str = "api_gateway",
    technique_ids: list[tuple[str, str]] | None = None,
) -> ThreatRecord:
    """Create a minimal ThreatRecord for testing."""
    if technique_ids is None:
        technique_ids = [("T1190", "Exploit Public-Facing Application")]
    mappings = []
    for tid, tname in technique_ids:
        mappings.append(TechniqueReference(
            framework="ATTACK",
            technique_id=tid,
            technique_name=tname,
            tactic="initial-access",
            mapping_rationale="Curated mapping",
            mapping_type="curated",
        ))
    return ThreatRecord(
        threat_id=f"{rule_id}-abc123",
        model_id="test-model",
        rule_id=rule_id,
        title="Test threat",
        description="A test threat record.",
        target_id=target_id,
        target_type="module",
        severity_hint="high",
        framework_mappings=mappings,
        rationale="Test rationale",
        created_at="2026-01-01T00:00:00+00:00",
    )


# ── Mitigation suggestion tests ─────��────────────────────────────


MITIGATION_ROWS = [
    {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "mitigation_id": "M1050",
        "mitigation_name": "Exploit Protection",
    },
    {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "mitigation_id": "M1030",
        "mitigation_name": "Network Segmentation",
    },
    {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "mitigation_id": "M1051",
        "mitigation_name": "Update Software",
    },
]


class TestSuggestedMitigations:

    def test_returns_mitigations_for_mapped_techniques(self) -> None:
        client = FakeEnrichClient(mitigation_rows=MITIGATION_ROWS)
        enricher = ThreatEnricher(client)  # type: ignore[arg-type]
        threat = _make_threat()
        model = FakeModel([FakeModule("api_gateway")])

        enricher.enrich([threat], model)  # type: ignore[arg-type]

        assert len(threat.suggested_mitigations) == 3
        assert all(isinstance(m, SuggestedMitigation) for m in threat.suggested_mitigations)
        ids = [m.mitigation_id for m in threat.suggested_mitigations]
        assert "M1050" in ids
        assert "M1030" in ids
        assert "M1051" in ids

    def test_filters_implemented_controls(self) -> None:
        client = FakeEnrichClient(mitigation_rows=MITIGATION_ROWS)
        enricher = ThreatEnricher(client)  # type: ignore[arg-type]
        threat = _make_threat()
        model = FakeModel([FakeModule("api_gateway", control_functions=["M1050"])])

        enricher.enrich([threat], model)  # type: ignore[arg-type]

        ids = [m.mitigation_id for m in threat.suggested_mitigations]
        assert "M1050" not in ids
        assert "M1030" in ids

    def test_deduplicates_mitigations(self) -> None:
        # Duplicate mitigation rows (from multiple technique matches)
        rows = MITIGATION_ROWS + [MITIGATION_ROWS[0]]
        client = FakeEnrichClient(mitigation_rows=rows)
        enricher = ThreatEnricher(client)  # type: ignore[arg-type]
        threat = _make_threat()
        model = FakeModel([FakeModule("api_gateway")])

        enricher.enrich([threat], model)  # type: ignore[arg-type]

        ids = [m.mitigation_id for m in threat.suggested_mitigations]
        assert len(ids) == len(set(ids))

    def test_respects_max_mitigations(self) -> None:
        client = FakeEnrichClient(mitigation_rows=MITIGATION_ROWS)
        enricher = ThreatEnricher(client)  # type: ignore[arg-type]
        threat = _make_threat()
        model = FakeModel([FakeModule("api_gateway")])

        enricher.enrich([threat], model, max_mitigations=1)  # type: ignore[arg-type]

        assert len(threat.suggested_mitigations) == 1

    def test_no_mappings_skips_enrichment(self) -> None:
        client = FakeEnrichClient(mitigation_rows=MITIGATION_ROWS)
        enricher = ThreatEnricher(client)  # type: ignore[arg-type]
        threat = _make_threat(technique_ids=[])
        model = FakeModel([FakeModule("api_gateway")])

        enricher.enrich([threat], model)  # type: ignore[arg-type]

        assert threat.suggested_mitigations == []
        assert threat.related_techniques == []
        # No queries should have been made
        assert len(client.calls) == 0

    def test_rationale_populated(self) -> None:
        client = FakeEnrichClient(mitigation_rows=MITIGATION_ROWS[:1])
        enricher = ThreatEnricher(client)  # type: ignore[arg-type]
        threat = _make_threat()
        model = FakeModel([FakeModule("api_gateway")])

        enricher.enrich([threat], model)  # type: ignore[arg-type]

        m = threat.suggested_mitigations[0]
        assert "M1050" in m.rationale or "Exploit Protection" in m.rationale
        assert "T1190" in m.rationale


# ── Related technique tests ────────��──────────────────────────────


SHARED_ROWS = [
    {
        "technique_id": "T1189",
        "technique_name": "Drive-by Compromise",
        "framework": "ATTACK",
        "shared_count": 3,
    },
    {
        "technique_id": "T1203",
        "technique_name": "Exploitation for Client Execution",
        "framework": "ATTACK",
        "shared_count": 2,
    },
]

HIERARCHY_ROWS = [
    {
        "technique_id": "T1190.001",
        "technique_name": "Exploit via Web Application",
        "framework": "ATTACK",
        "relationship": "subtechnique",
    },
]


class TestRelatedTechniques:

    def test_finds_shared_mitigation_techniques(self) -> None:
        client = FakeEnrichClient(shared_rows=SHARED_ROWS)
        enricher = ThreatEnricher(client)  # type: ignore[arg-type]
        threat = _make_threat()
        model = FakeModel([FakeModule("api_gateway")])

        enricher.enrich([threat], model)  # type: ignore[arg-type]

        related_ids = [r.technique_id for r in threat.related_techniques]
        assert "T1189" in related_ids
        assert all(isinstance(r, RelatedTechnique) for r in threat.related_techniques)

    def test_shared_mitigation_relationship_type(self) -> None:
        client = FakeEnrichClient(shared_rows=SHARED_ROWS)
        enricher = ThreatEnricher(client)  # type: ignore[arg-type]
        threat = _make_threat()
        model = FakeModel([FakeModule("api_gateway")])

        enricher.enrich([threat], model)  # type: ignore[arg-type]

        for r in threat.related_techniques:
            if r.technique_id in ("T1189", "T1203"):
                assert r.relationship == "shared-mitigation"
                assert r.shared_mitigations > 0

    def test_finds_hierarchy_techniques(self) -> None:
        client = FakeEnrichClient(hierarchy_rows=HIERARCHY_ROWS)
        enricher = ThreatEnricher(client)  # type: ignore[arg-type]
        threat = _make_threat()
        model = FakeModel([FakeModule("api_gateway")])

        enricher.enrich([threat], model)  # type: ignore[arg-type]

        related_ids = [r.technique_id for r in threat.related_techniques]
        assert "T1190.001" in related_ids
        sub = next(r for r in threat.related_techniques if r.technique_id == "T1190.001")
        assert sub.relationship == "subtechnique"

    def test_respects_max_related(self) -> None:
        client = FakeEnrichClient(shared_rows=SHARED_ROWS, hierarchy_rows=HIERARCHY_ROWS)
        enricher = ThreatEnricher(client)  # type: ignore[arg-type]
        threat = _make_threat()
        model = FakeModel([FakeModule("api_gateway")])

        enricher.enrich([threat], model, max_related=1)  # type: ignore[arg-type]

        assert len(threat.related_techniques) <= 1

    def test_excludes_curated_technique_ids(self) -> None:
        # T1190 is already mapped; shared results should exclude it
        shared = SHARED_ROWS + [{
            "technique_id": "T1190",
            "technique_name": "Exploit Public-Facing Application",
            "framework": "ATTACK",
            "shared_count": 5,
        }]
        client = FakeEnrichClient(shared_rows=shared)
        enricher = ThreatEnricher(client)  # type: ignore[arg-type]
        threat = _make_threat()
        model = FakeModel([FakeModule("api_gateway")])

        enricher.enrich([threat], model)  # type: ignore[arg-type]

        related_ids = [r.technique_id for r in threat.related_techniques]
        assert "T1190" not in related_ids


# ── Backward compatibility tests ───────���──────────────────────────


class TestBackwardCompatibility:

    def test_default_empty_fields(self) -> None:
        """ThreatRecord without enrichment has empty suggested_mitigations and related_techniques."""
        threat = _make_threat()
        assert threat.suggested_mitigations == []
        assert threat.related_techniques == []

    def test_serialization_roundtrip(self) -> None:
        """Enriched ThreatRecord survives JSON serialization."""
        client = FakeEnrichClient(
            mitigation_rows=MITIGATION_ROWS[:1],
            shared_rows=SHARED_ROWS[:1],
        )
        enricher = ThreatEnricher(client)  # type: ignore[arg-type]
        threat = _make_threat()
        model = FakeModel([FakeModule("api_gateway")])

        enricher.enrich([threat], model)  # type: ignore[arg-type]

        data = threat.model_dump()
        restored = ThreatRecord(**data)
        assert len(restored.suggested_mitigations) == 1
        assert len(restored.related_techniques) == 1
        assert restored.suggested_mitigations[0].mitigation_id == "M1050"

    def test_multiple_threats_enriched(self) -> None:
        """All threats in a batch are enriched."""
        client = FakeEnrichClient(mitigation_rows=MITIGATION_ROWS[:1])
        enricher = ThreatEnricher(client)  # type: ignore[arg-type]
        threats = [_make_threat(rule_id="TH-001"), _make_threat(rule_id="TH-002")]
        model = FakeModel([FakeModule("api_gateway")])

        result = enricher.enrich(threats, model)  # type: ignore[arg-type]

        assert result is threats  # enriches in-place
        for t in threats:
            assert len(t.suggested_mitigations) > 0

    def test_enrich_returns_same_list(self) -> None:
        """enrich() returns the same list object it was given."""
        client = FakeEnrichClient()
        enricher = ThreatEnricher(client)  # type: ignore[arg-type]
        threats = [_make_threat()]
        model = FakeModel([FakeModule("api_gateway")])

        result = enricher.enrich(threats, model)  # type: ignore[arg-type]

        assert result is threats
