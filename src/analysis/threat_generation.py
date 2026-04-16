from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


Framework = Literal["ATTACK", "ATLAS"]


@dataclass(frozen=True)
class ThreatHeuristic:
    rule_id: str
    name: str
    description: str
    graph_pattern: str
    target_type: Literal["module", "workflow", "object", "datastore", "system"]
    severity_hint: Literal["low", "medium", "high", "critical"]
    frameworks: tuple[Framework, ...]
    output_field_mapping: tuple[str, ...]


THREAT_HEURISTICS: tuple[ThreatHeuristic, ...] = (
    ThreatHeuristic(
        rule_id="TH-001",
        name="Internet exposed module handling sensitive workflow data",
        description=(
            "Detect modules reachable from the internet that participate in workflows "
            "handling confidential, secret, or regulated objects."
        ),
        graph_pattern=(
            "(m:Module {internet_exposed:true})<-[:INVOLVES_MODULE]-(w:Workflow)-"
            "[:INVOLVES_OBJECT]->(o:Object) WHERE o.classification IN ['confidential','secret'] "
            "OR o.regulated=true"
        ),
        target_type="module",
        severity_hint="high",
        frameworks=("ATTACK",),
        output_field_mapping=(
            "target_id <- module.id",
            "target_type <- 'module'",
            "affected_workflows <- workflow.id",
            "affected_objects <- object.id",
            "rationale <- internet exposure + sensitive data handling",
        ),
    ),
    ThreatHeuristic(
        rule_id="TH-002",
        name="Low-trust to high-value object dependency path",
        description=(
            "Identify dependency chains beginning in low-trust domains and ending at "
            "confidential, secret, or regulated objects through datastores."
        ),
        graph_pattern=(
            "(src:Module)-[:IN_DOMAIN]->(:SecurityDomain {trust_level:'low'}), "
            "path via [:DEPENDS_ON*] to (:DataStore)-[:STORES]->(o:Object high-value)"
        ),
        target_type="object",
        severity_hint="critical",
        frameworks=("ATTACK",),
        output_field_mapping=(
            "target_id <- object.id",
            "target_type <- 'object'",
            "exposure_path <- dependency path",
            "affected_modules <- entry and pivot modules",
            "rationale <- low-trust reachability to high-value data",
        ),
    ),
    ThreatHeuristic(
        rule_id="TH-003",
        name="High-privilege module externally reachable",
        description=(
            "Flag modules with service/admin privilege that are internet-exposed or "
            "reachable through workflows involving external actors."
        ),
        graph_pattern=(
            "(m:Module)-[:HAS_PRIVILEGE]->(p:PrivilegeLevel {level>=2}) AND "
            "(m.internet_exposed=true OR EXISTS external actor workflow path)"
        ),
        target_type="module",
        severity_hint="high",
        frameworks=("ATTACK",),
        output_field_mapping=(
            "target_id <- module.id",
            "privilege_level <- privilege.level",
            "external_reachability <- internet_exposed|workflow_actor_path",
            "rationale <- privilege + exposure combination",
        ),
    ),
    ThreatHeuristic(
        rule_id="TH-004",
        name="AI-relevant module dependency and model service exposure",
        description=(
            "Detect modules that depend on AI-relevant services and can influence model "
            "inputs, feature stores, or inference surfaces."
        ),
        graph_pattern=(
            "(m:Module)-[:DEPENDS_ON]->(ai:Module {ai_relevant:true}) OR "
            "workflow path to ai_relevant datastore/object"
        ),
        target_type="module",
        severity_hint="high",
        frameworks=("ATLAS", "ATTACK"),
        output_field_mapping=(
            "target_id <- ai module.id",
            "target_type <- 'module'",
            "ai_surface <- model/feature data path",
            "rationale <- AI service dependency with potential manipulation",
        ),
    ),
    ThreatHeuristic(
        rule_id="TH-005",
        name="Regulated object concentration in critical workflows",
        description=(
            "Highlight workflows in high or critical systems that involve multiple "
            "regulated objects and privileged modules."
        ),
        graph_pattern=(
            "(s:System {criticality in ['high','critical']})-[:HAS_WORKFLOW]->(w)-"
            "[:INVOLVES_OBJECT]->(o:Object {regulated:true}) and workflow privileged modules"
        ),
        target_type="workflow",
        severity_hint="high",
        frameworks=("ATTACK",),
        output_field_mapping=(
            "target_id <- workflow.id",
            "affected_objects <- regulated object ids",
            "affected_modules <- privileged module ids",
            "system_criticality <- system.criticality",
            "rationale <- regulated data in critical workflow",
        ),
    ),
    ThreatHeuristic(
        rule_id="TH-006",
        name="Trust boundary crossing with privileged dependency",
        description=(
            "Detect dependencies that traverse defined trust boundaries and terminate "
            "in privileged backend or datastore components."
        ),
        graph_pattern=(
            "(tb:TrustBoundary)-[:CROSSES_FROM]->(from), (tb)-[:CROSSES_TO]->(to), "
            "(src)-[:IN_DOMAIN]->(from), (src)-[:DEPENDS_ON]->(dst)-[:IN_DOMAIN]->(to), "
            "dst privilege >= service or datastore with sensitive objects"
        ),
        target_type="module",
        severity_hint="medium",
        frameworks=("ATTACK",),
        output_field_mapping=(
            "target_id <- destination module/datastore id",
            "trust_boundary <- trust boundary id",
            "dependency_relationship <- DEPENDS_ON.relationship",
            "rationale <- boundary crossing into privileged/sensitive zone",
        ),
    ),
)


def get_threat_heuristics() -> tuple[ThreatHeuristic, ...]:
    """Return immutable heuristic catalog used by the threat generation engine."""

    return THREAT_HEURISTICS
