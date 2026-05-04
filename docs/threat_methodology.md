# Threat Methodology v0.2

This document defines the deterministic threat heuristic catalog.

## Objectives
- define reproducible graph-driven threat heuristics
- map each heuristic to clear output fields
- provide ATT&CK/ATLAS alignment hooks
- support GraphRAG-enriched threat records with suggested mitigations and related techniques

## Heuristic summary

The engine runs **44 heuristics** (TH-001 through TH-044) across four expansion phases:

| Phase | Rules | Focus |
|---|---|---|
| Phase 0 (original) | TH-001 – TH-006 | Core structural patterns |
| Phase 1 (STRIDE) | TH-007 – TH-014 | STRIDE-per-element enumeration |
| Phase 2 (CAPEC) | TH-015 – TH-024 | CAPEC Meta/Standard gap fill |
| Phase 3 (Enrichment) | TH-025 – TH-034 | Control-absence detection (auth, encryption, validation) |
| Phase 4 (NIST 800-53) | TH-035 – TH-044 | Control-gap detection (NIST control families) |

See [design_heuristics.md](design_heuristics.md) for full expansion details, CAPEC mappings, and schema enrichment properties.

## Phase 0 rule catalog

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
- `suggested_mitigations` (populated by GraphRAG enrichment, default `[]`)
- `related_techniques` (populated by GraphRAG enrichment, default `[]`)

## Implementation notes
- Each heuristic can be defined in one of two formats, both auto-discovered at import time:
  - **TOML** (`src/analysis/heuristics/rules/th_*.toml`) — a config-driven format with `[heuristic]` and `[materializer]` sections. The `GenericMaterializer` class interprets the materializer config at runtime, supporting primary-key iteration, filtering, cross-reference collection, and per-row joins. This is the preferred format for new heuristics that follow standard patterns.
  - **Python** (`src/analysis/heuristics/th_*.py`) — a standalone module containing both the `ThreatHeuristic` dataclass definition (`HEURISTIC`) and a `ThreatMaterializer` class. Use this format for heuristics requiring complex logic that cannot be expressed declaratively.
  - Python modules take precedence when both formats define the same `rule_id`. Discovery uses `pkgutil.iter_modules` for Python and `pathlib.glob` for TOML.
- Technique mapping is exposed through `src/analysis/mapping_catalog.py`, `mapping_engine.py`, `mapping_loader.py`, and `mapping_types.py`. Each `rule_id` is bound to ATT&CK/ATLAS technique IDs and names.
- **Graph-backed technique suggestion** is implemented in `src/analysis/graphrag_scorer.py`. It blends vector similarity (45%) with tactic overlap (15%), framework match (10%), mitigation gap (20%), and sub-technique bonus (10%). The mitigation-gap signal compares technique mitigations against the target module's `control_functions`. `threatforge suggest-mappings` always uses this scorer.
- **Runtime threat enrichment** (`src/analysis/threat_enricher.py`) traverses the MITRE knowledge graph after materialization to add `suggested_mitigations` and `related_techniques` to each `ThreatRecord`. Enabled via `--enrich` flag or `THREATFORGE_GRAPHRAG=1` env var.
- **Sync-time batch mapping** (`src/analysis/mapping_writer.py`) extends `threatforge sync --map-heuristics` to score all discovered heuristics in one pass and write `data/threat_intel/mapping_suggestions.toml`. The output file uses `mapping_type = "suggested"` and is regenerated on each run. Configurable via `--map-threshold` (default 0.40) and `--map-top-k` (default 10). Curated mappings are excluded from suggestions and never overwritten. The `[suggestions]` section in `mapping_config.toml` controls whether suggested mappings are included at analysis time (`include_suggested = false` by default).
- Structured threat generation is orchestrated by `src/analysis/threat_outputs.py`, which iterates auto-discovered materializers via `materializer_registry.py` and persists outputs to `models/outputs/threats/`.
