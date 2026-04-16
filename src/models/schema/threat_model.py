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
    created_at: str


class ThreatReport(BaseModel):
    model_id: str
    generated_at: str
    threat_count: int
    threats: list[ThreatRecord] = Field(default_factory=list)
