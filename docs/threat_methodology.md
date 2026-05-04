# Threat Methodology

This document describes how the threat engine works today.

## Purpose

The threat engine turns a validated architecture model into structured threat records. It does this by applying deterministic heuristics to graph-backed views of the model.

Each output threat has:

- a stable `rule_id`
- a target entity
- a severity hint
- rationale text
- ATT&CK / ATLAS technique mappings
- optional enrichment data

## Threat Generation Flow

1. Load the validated model into Neo4j.
2. Resolve the graph views required by each heuristic.
3. Materialize matching threats.
4. Map each rule to ATT&CK / ATLAS techniques.
5. Optionally enrich threats with mitigations and related techniques.
6. Write the final threat report.

## Heuristic Model

Threat rules live under `src/analysis/heuristics/`.

Two formats are supported:

- TOML rule files in `src/analysis/heuristics/rules/`
- Python rule modules in `src/analysis/heuristics/`

Heuristics are auto-discovered. Each one produces threats for a specific graph pattern or control gap.

## Rule Set

The current engine runs 44 heuristics:

| Range | Focus |
|---|---|
| `TH-001` to `TH-006` | Core exposure, trust, privilege, AI, and regulated-data patterns |
| `TH-007` to `TH-014` | STRIDE-style expansions |
| `TH-015` to `TH-024` | CAPEC-oriented expansions |
| `TH-025` to `TH-034` | Schema and control-absence checks |
| `TH-035` to `TH-044` | NIST 800-53 style control-gap checks |

## Snapshot Resolution

Threat generation does not build one eager global snapshot anymore.

Instead:

- each materializer declares the graph views it needs
- `ThreatSnapshotResolver` loads those views lazily
- results are cached for the current run

This keeps threat generation explicit and scalable as the heuristic set grows.

## Technique Mapping

Technique mapping is split across:

- `src/analysis/mapping_catalog.py`
- `src/analysis/mapping_loader.py`
- `src/analysis/mapping_engine.py`
- `src/analysis/mapping_types.py`

The mapping pipeline can include:

1. curated mappings
2. optional suggested mappings
3. optional tactic-based expansion
4. optional context filtering

Curated mappings are the primary source of truth.

## Suggested Mappings

Suggested mappings are generated from the graph-backed knowledge pipeline.

Relevant code:
- `src/analysis/graphrag_scorer.py`
- `src/analysis/mapping_writer.py`

They are:

- generated offline
- written to `data/threat_intel/mapping_suggestions.toml`
- reviewable before promotion
- optionally included during analysis through mapping config

## Threat Enrichment

When enabled, enrichment adds:

- suggested mitigations
- related techniques

Relevant code:
- `src/analysis/threat_enricher.py`

Enrichment uses the Neo4j knowledge graph. It does not change threat selection; it adds supporting context to the threat records already produced.

## Output Contract

Threat reports are written to `models/outputs/threats/`.

Each threat record includes:

- `threat_id`
- `rule_id`
- `title`
- `target_id`
- `target_type`
- `severity_hint`
- `rationale`
- `framework_mappings`
- `evidence`
- `suggested_mitigations`
- `related_techniques`

## Practical Use

Use this layer when you want to:

- see which architecture patterns triggered findings
- understand why a threat applies
- trace a threat to ATT&CK / ATLAS techniques
- inspect optional mitigation and related-technique context

Use [docs/risk_methodology.md](risk_methodology.md) for the next step in the pipeline.
