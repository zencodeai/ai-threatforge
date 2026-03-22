# Graph Schema v0.1

This document defines how the canonical TOML model is represented in Neo4j for Phase 2.

## Goals
- preserve model semantics from `CanonicalModel`
- support idempotent loading with `MERGE`
- enable threat and risk traversal queries
- keep initial schema explicit and easy to evolve

## Node labels
- `System`
  - keys: `id`
  - properties: `name`, `description`, `criticality`, `industry`
- `SecurityDomain`
  - keys: `id`
  - properties: `name`, `trust_level`
- `PrivilegeLevel`
  - keys: `id`
  - properties: `level`, `description`
- `Module`
  - keys: `id`
  - properties: `name`, `module_type`, `internet_exposed`, `processes_sensitive_data`, `ai_relevant`, `description`
- `Object`
  - keys: `id`
  - properties: `name`, `object_type`, `classification`, `regulated`, `ai_relevant`
- `DataStore`
  - keys: `id`
  - properties: `name`, `store_type`, `ai_relevant`
- `ExternalActor`
  - keys: `id`
  - properties: `name`, `actor_type`
- `Workflow`
  - keys: `id`
  - properties: `name`, `description`, `steps`
- `TrustBoundary`
  - keys: `id`
  - properties: `name`

## Relationships
- `(Module)-[:IN_DOMAIN]->(SecurityDomain)`
- `(DataStore)-[:IN_DOMAIN]->(SecurityDomain)`
- `(Module)-[:HAS_PRIVILEGE]->(PrivilegeLevel)`
- `(DataStore)-[:STORES]->(Object)`
- `(Workflow)-[:INVOLVES_MODULE]->(Module)`
- `(Workflow)-[:INVOLVES_OBJECT]->(Object)`
- `(TrustBoundary)-[:CROSSES_FROM]->(SecurityDomain)`
- `(TrustBoundary)-[:CROSSES_TO]->(SecurityDomain)`
- `(ExternalActor)-[:PARTICIPATES_IN]->(Workflow)` (derived from workflow step text)
- `(Module)-[:DEPENDS_ON {relationship}]->(Module|DataStore)`
- `(System)-[:HAS_DOMAIN]->(SecurityDomain)`
- `(System)-[:HAS_MODULE]->(Module)`
- `(System)-[:HAS_DATASTORE]->(DataStore)`
- `(System)-[:HAS_OBJECT]->(Object)`
- `(System)-[:HAS_WORKFLOW]->(Workflow)`
- `(System)-[:HAS_BOUNDARY]->(TrustBoundary)`

## Constraints
Each primary node label has a unique `id` constraint.

## Indexes
Initial indexes prioritize common filtering fields:
- `Module.internet_exposed`
- `Module.ai_relevant`
- `Object.classification`
- `Object.regulated`
- `Workflow.id`

## Idempotency
Loader behavior is idempotent by design:
- nodes are loaded with `MERGE` on `id`
- relationships are loaded with deterministic pattern `MERGE`
- constraints and indexes use `IF NOT EXISTS`

## Notes
- Workflow actor participation is inferred by parsing `workflow.steps` where step source matches `external_actors[].id`.
- Dependency edge preserves the source TOML `relationship` field as relationship property.
