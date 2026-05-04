# Threat Forge AI Architecture

This document describes the system as it works today.

## System Flow

1. A canonical system model is loaded from TOML.
2. The model is validated with Pydantic and cross-reference checks.
3. The validated model is projected into Neo4j.
4. Threat heuristics run against graph-backed views of the model.
5. Threats are mapped to ATT&CK / ATLAS techniques.
6. Risks are scored from the generated threats.
7. CLI, UI, and the analyst query workflow consume the resulting artifacts.

The core analysis path is deterministic.

## Main Layers

### Canonical Model

Code:
- `src/models/schema/canonical_model.py`
- `src/models/schema/threat_model.py`
- `src/models/schema/risk_model.py`

Purpose:
- define the architecture input contract
- define the threat and risk output contracts

Key points:
- TOML is the source format
- validation rejects dangling references and duplicate IDs
- downstream layers only operate on validated models

### Graph Layer

Code:
- `src/graph/neo4j_client.py`
- `src/graph/graph_loader.py`
- `src/graph/graph_queries.py`

Purpose:
- load the system model into Neo4j
- provide named graph queries used by analysis and agent tools

Key points:
- graph loading is idempotent
- query ownership is centralized in `graph_queries.py`
- analyst-facing graph access goes through stable query IDs, not raw Cypher in the agent layer

### Knowledge Layer

Code:
- `src/knowledge/store.py`
- `src/knowledge/index.py`
- `src/knowledge/provider.py`
- `src/knowledge/sync.py`

Purpose:
- sync ATT&CK and ATLAS data
- provide a local technique catalog
- support graph-backed retrieval and enrichment

Key points:
- SQLite stores synced ATT&CK / ATLAS metadata
- Neo4j stores the graph-backed knowledge representation used for chunking, vector search, and enrichment
- `KnowledgeProvider` owns refreshable index access for long-lived runtime paths

### Analysis Layer

Code:
- `src/analysis/threat_outputs.py`
- `src/analysis/snapshot_resolver.py`
- `src/analysis/mapping_engine.py`
- `src/analysis/mapping_catalog.py`
- `src/analysis/risk_scoring.py`

Purpose:
- generate threats
- map threats to ATT&CK / ATLAS techniques
- enrich threats when enabled
- score risks

Key points:
- heuristics are auto-discovered from `src/analysis/heuristics/`
- threat generation is dependency-driven through `ThreatSnapshotResolver`
- technique mapping combines curated mappings, optional suggestions, and optional tactic expansion
- risk scoring is deterministic and artifact-based

### Application Services

Code:
- `src/app/analysis_service.py`
- `src/app/knowledge_service.py`

Purpose:
- share orchestration between CLI and UI

Key points:
- CLI and UI do not maintain separate pipeline logic
- services return structured success and failure results
- service failures preserve error code, step, and exception type

### Session and Manifest Layer

Code:
- `src/session_store.py`
- `src/analysis_manifest.py`
- `src/report_repository.py`
- `src/project_paths.py`

Purpose:
- persist the active analysis context
- resolve the correct threat and risk artifacts

Key points:
- session state is shared by CLI and UI
- analysis manifests bind a model to the exact generated artifacts
- artifact resolution prefers the active manifest over filesystem discovery

### Agent Query Layer

Code:
- `src/agents/router.py`
- `src/agents/executor.py`
- `src/agents/composer.py`
- `src/agents/workflow.py`
- `src/agents/tools.py`
- `src/agents/observability.py`

Purpose:
- answer analyst questions over graph, threat, risk, and knowledge artifacts

Key points:
- routing is deterministic
- tools return structured results
- answers are grounded in artifact or graph evidence
- trace events capture workflow start, tool results, workflow errors, and workflow end

### UI Layer

Code:
- `src/ui/app.py`
- `src/ui/runtime.py`
- `src/ui/report_data.py`
- `src/ui/mapping_data.py`
- `src/ui/pages/`

Purpose:
- provide an analyst interface over the current session and artifacts

Key points:
- UI runtime construction is explicit
- report and mapping data access are split by responsibility
- rebuild and sync actions use the shared service layer

## Runtime Paths

The most common runtime paths are:

### Analysis pipeline

```text
model.toml
  -> validate
  -> load graph
  -> generate threats
  -> score risks
  -> write manifest
```

### Knowledge sync

```text
ATT&CK / ATLAS sync
  -> local store update
  -> optional Neo4j knowledge load
  -> optional text chunk embedding
  -> optional mapping suggestion generation
```

### Analyst query

```text
question
  -> route to tool(s)
  -> execute over graph / artifacts / knowledge
  -> compose grounded answer
  -> trace the run
```

## Artifacts

Generated artifacts live under `models/outputs/`:

- `threats/`
- `risks/`
- `manifests/`
- `traces/`

These artifacts are first-class system outputs. The UI and agent workflow read them directly.

## Extension Points

- Add new heuristics in `src/analysis/heuristics/`
- Add new named graph queries in `src/graph/graph_queries.py`
- Extend knowledge sync in `src/knowledge/sync.py`
- Add new analyst tools in `src/agents/tools.py`
- Add new UI screens in `src/ui/pages/`

## Operational Model

- Use the CLI to set or inspect the active session.
- Use manifests to keep runs traceable.
- Use the UI and agent workflow as consumers of generated artifacts, not as alternate sources of truth.
- Treat the model, threat report, and risk report as the audit boundary for analysis.
