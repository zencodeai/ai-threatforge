from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator


class RiskFactors(BaseModel):
    likelihood: float = Field(ge=0.0, le=1.0)
    impact: float = Field(ge=0.0, le=1.0)
    exposure: float = Field(ge=0.0, le=1.0)
    privilege_sensitivity: float = Field(ge=0.0, le=1.0)
    data_criticality: float = Field(ge=0.0, le=1.0)
    exploitability: float = Field(ge=0.0, le=1.0)


class RiskDriver(BaseModel):
    factor: Literal[
        "likelihood",
        "impact",
        "exposure",
        "privilege_sensitivity",
        "data_criticality",
        "exploitability",
    ]
    score: float = Field(ge=0.0, le=1.0)
    weighted_contribution: float = Field(ge=0.0, le=1.0)


class RiskRecord(BaseModel):
    risk_id: str
    model_id: str
    threat_id: str
    rule_id: str
    title: str
    target_id: str
    target_type: Literal["module", "workflow", "object", "datastore", "system"]
    risk_score: float = Field(ge=0.0, le=1.0)
    priority: Literal["low", "medium", "high", "critical"]
    factors: RiskFactors
    drivers: list[RiskDriver] = Field(default_factory=list)
    explanation: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    created_at: str


class RiskReport(BaseModel):
    model_id: str
    generated_at: str
    methodology_version: str = "0.1"
    risk_count: int
    risks: list[RiskRecord] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_count(self) -> "RiskReport":
        if self.risk_count != len(self.risks):
            raise ValueError(
                f"risk_count ({self.risk_count}) does not match risks length ({len(self.risks)})"
            )
        return self
