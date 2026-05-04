# Project Kit

This document is a compact orientation guide for working on the codebase.

## What The System Is

Threat Forge AI is a local-first, model-driven threat analysis system.

Its primary inputs are:
- a canonical TOML model
- synced ATT&CK / ATLAS knowledge
- Neo4j state for architecture and knowledge queries

Its primary outputs are:
- threat reports
- risk reports
- analysis manifests
- analyst query traces

## Main Runtime Paths

### Analysis

```text
model
  -> validate
  -> load graph
  -> generate threats
  -> score risks
  -> update session + manifest
```

### Knowledge sync

```text
sync ATT&CK / ATLAS
  -> update local store
  -> optionally load Neo4j knowledge graph
  -> optionally create text chunks
  -> optionally generate mapping suggestions
```

### Analyst query

```text
question
  -> route
  -> execute tool(s)
  -> compose answer
  -> trace run
```

## Module Map

| Area | Key code |
|---|---|
| Model schema | `src/models/schema/` |
| Graph loading and queries | `src/graph/` |
| Knowledge sync and provider | `src/knowledge/` |
| Threat and risk analysis | `src/analysis/` |
| Shared services | `src/app/` |
| Session, manifests, artifact resolution | `src/session_store.py`, `src/analysis_manifest.py`, `src/report_repository.py` |
| Agent workflow | `src/agents/` |
| UI | `src/ui/` |
| CLI | `src/cli/main.py` |

## Key Operational Concepts

### Session

The shared session records the active model and active artifact set. CLI and UI both use it.

### Manifest

The analysis manifest binds:
- model
- threat artifact
- risk artifact

This is the preferred resolution path for downstream readers.

### Determinism

Core analysis is deterministic:
- validation
- graph loading
- threat generation
- risk scoring
- query routing

### Services

`AnalysisService` and `KnowledgeService` are the shared orchestration surface for CLI and UI.

## Common Commands

```bash
threatforge session --model examples/fintech_ai_platform.toml
threatforge validate
threatforge load-graph --clear
threatforge generate-threats
threatforge score-risks
threatforge sync --status
threatforge ui
```

## Development Notes

- Prefer working through services rather than duplicating orchestration in UI or CLI code.
- Add new graph queries in `src/graph/graph_queries.py`.
- Add new heuristics in `src/analysis/heuristics/`.
- Keep outputs artifact-based and traceable.
- Preserve deterministic behavior in the analysis and query paths.
