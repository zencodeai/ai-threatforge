# Canonical Model v0.1

## Scope
This document defines the canonical TOML model and validation assumptions.

## Top-level sections
- `meta`
- `system`
- `security_domains`
- `privilege_levels`
- `modules`
- `objects`
- `datastores`
- `external_actors`
- `workflows`
- `trust_boundaries`
- `dependencies`

## Required cross-reference rules
- `modules[].domain` must exist in `security_domains[].id`
- `modules[].privilege` must exist in `privilege_levels[].id`
- `datastores[].domain` must exist in `security_domains[].id`
- `datastores[].contains[]` must exist in `objects[].id`
- `workflows[].modules[]` must exist in `modules[].id`
- `workflows[].objects[]` must exist in `objects[].id`
- `trust_boundaries[].from_domain` and `to_domain` must exist in `security_domains[].id`
- `dependencies[].source` must exist in `modules[].id`
- `dependencies[].target` must exist in `modules[].id` or `datastores[].id`

## Identity constraints
Unique ids are required for:
- security domains
- privilege levels
- modules
- objects
- datastores

## Validation interface
- Load and validate model with `src/models/schema/canonical_model.py`
- CLI: `threatforge validate --model <path>`
