# Threat Methodology v0.1

This document defines the deterministic threat heuristic catalog.

## Objectives
- define reproducible graph-driven threat heuristics
- map each heuristic to clear output fields
- provide ATT&CK/ATLAS alignment hooks for Phase 3 mapping work

## Rule catalog

### TH-001: Internet exposed module handling sensitive workflow data
- Intent: detect initial access and data exposure candidates.
- Pattern:
  - internet-exposed module participates in a workflow
  - workflow involves confidential, secret, or regulated object
- Target: `module`
- Severity hint: `high`
- Frameworks: `ATTACK`
- Output field mapping:
  - `target_id <- module.id`
  - `target_type <- module`
  - `affected_workflows <- workflow.id[]`
  - `affected_objects <- object.id[]`
  - `rationale <- internet exposure + sensitive data handling`

### TH-002: Low-trust to high-value object dependency path
- Intent: detect attack paths from low-trust origins to high-value assets.
- Pattern:
  - source module in low-trust domain
  - dependency path reaches datastore containing confidential/secret/regulated object
- Target: `object`
- Severity hint: `critical`
- Frameworks: `ATTACK`
- Output field mapping:
  - `target_id <- object.id`
  - `target_type <- object`
  - `exposure_path <- path modules/datastores`
  - `affected_modules <- pivot module ids`
  - `rationale <- low-trust reachability to high-value data`

### TH-003: High-privilege module externally reachable
- Intent: detect privilege misuse and high-impact lateral movement candidates.
- Pattern:
  - module privilege level >= service
  - module is internet-exposed or reachable via external actor workflow path
- Target: `module`
- Severity hint: `high`
- Frameworks: `ATTACK`
- Output field mapping:
  - `target_id <- module.id`
  - `privilege_level <- privilege.level`
  - `external_reachability <- internet|workflow`
  - `rationale <- privilege + exposure`

### TH-004: AI-relevant module dependency and model service exposure
- Intent: identify AI/ML attack surfaces (poisoning/evasion/exfiltration candidates).
- Pattern:
  - module depends on AI-relevant module
  - or workflow/data path includes AI-relevant datastore/object
- Target: `module`
- Severity hint: `high`
- Frameworks: `ATLAS`, `ATTACK`
- Output field mapping:
  - `target_id <- ai module.id`
  - `ai_surface <- model or feature path`
  - `affected_workflows <- workflow.id[]`
  - `rationale <- AI dependency with manipulable inputs/outputs`

### TH-005: Regulated object concentration in critical workflows
- Intent: prioritize workflows that combine regulatory impact and high system criticality.
- Pattern:
  - system criticality is high/critical
  - workflow has multiple regulated objects and privileged modules
- Target: `workflow`
- Severity hint: `high`
- Frameworks: `ATTACK`
- Output field mapping:
  - `target_id <- workflow.id`
  - `system_criticality <- system.criticality`
  - `affected_objects <- regulated object ids`
  - `affected_modules <- privileged module ids`
  - `rationale <- regulated data in critical workflow`

### TH-006: Trust boundary crossing with privileged dependency
- Intent: detect risky domain transitions to privileged or sensitive components.
- Pattern:
  - dependency crosses defined trust boundary from one domain to another
  - destination is privileged module or sensitive datastore path
- Target: `module`
- Severity hint: `medium`
- Frameworks: `ATTACK`
- Output field mapping:
  - `target_id <- destination component id`
  - `trust_boundary <- trust boundary.id`
  - `dependency_relationship <- DEPENDS_ON.relationship`
  - `rationale <- trust boundary crossing into privileged/sensitive zone`

## Output contract guidance
Threat objects generated from these heuristics should include at minimum:
- `threat_id`
- `rule_id`
- `title`
- `target_id`
- `target_type`
- `severity_hint`
- `framework_mappings`
- `rationale`
- `evidence`

## Implementation notes
- Each heuristic is defined as a standalone module in `src/analysis/heuristics/` (e.g., `th_001.py`), containing both the `ThreatHeuristic` dataclass definition (`HEURISTIC`) and a `ThreatMaterializer` class. Heuristics are auto-discovered at import time via `pkgutil.iter_modules` — adding a new heuristic requires only a new `th_*.py` module.
- Technique mapping is exposed through the facade `src/analysis/technique_mapping.py`, which delegates to `mapping_engine.py` (curated + tactic-expansion + context-filtering pipeline), `mapping_loader.py` (TOML I/O and name resolution), and `mapping_types.py` (data model). Each `rule_id` is bound to ATT&CK/ATLAS technique IDs and names.
- Structured threat generation is orchestrated by `src/analysis/threat_outputs.py`, which iterates auto-discovered materializers via `materializer_registry.py` and persists outputs to `models/outputs/threats/`.
