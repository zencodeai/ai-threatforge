from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class TechniqueReference(BaseModel):
    framework: Literal["ATTACK", "ATLAS"]
    technique_id: str
    technique_name: str
    tactic: str
    mapping_rationale: str
    mapping_type: Literal["curated", "tactic-expansion"] = "curated"


class SuggestedMitigation(BaseModel):
    """A mitigation suggested by GraphRAG enrichment."""

    mitigation_id: str
    name: str
    technique_id: str
    technique_name: str
    rationale: str


class RelatedTechnique(BaseModel):
    """A technique discovered via graph traversal (shared mitigations / sub-technique)."""

    technique_id: str
    technique_name: str
    framework: str
    relationship: Literal["shared-mitigation", "subtechnique", "parent"]
    shared_mitigations: int = 0


class ThreatRecord(BaseModel):
    threat_id: str
    model_id: str
    rule_id: str
    title: str
    description: str
    target_id: str
    target_type: Literal["module", "workflow", "object", "datastore", "system"]
    severity_hint: Literal["low", "medium", "high", "critical"]
    framework_mappings: list[TechniqueReference] = Field(default_factory=list)
    rationale: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    affected_workflows: list[str] = Field(default_factory=list)
    affected_objects: list[str] = Field(default_factory=list)
    suggested_mitigations: list[SuggestedMitigation] = Field(default_factory=list)
    related_techniques: list[RelatedTechnique] = Field(default_factory=list)
    created_at: str


class ThreatReport(BaseModel):
    model_id: str
    generated_at: str
    threat_count: int
    threats: list[ThreatRecord] = Field(default_factory=list)
