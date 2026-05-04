## Architecture Refactor Plan

This plan turns the current architecture review into an implementation roadmap with low-risk sequencing. The goal is to improve correctness and extensibility without destabilizing the deterministic analysis core.

### Guiding rules

1. Keep threat generation, risk scoring, and query answers deterministic.
2. Prefer new service boundaries over broad rewrites in place.
3. Move shared concerns behind typed APIs before changing behavior.
4. Add regression tests before replacing an existing entry point.

### Phase 0: Low-risk groundwork

Status: completed on `architecture-review`.

Completed:
- Added a shared session store used by both CLI and UI.
- Persisted active model and artifact paths across CLI calls and UI sessions.
- Made report loading prefer the session artifact before falling back to discovery.
- Added focused regression tests for session persistence and CLI/UI resolution.

Delivered in this phase:
- Replaced lexicographic artifact fallback with mtime-based selection.
- Reduced default-path coupling in CLI/UI session-aware flows by adding path/session injection points.
- Added session-aware integration tests for the Streamlit app shell.

Why first:
- This reduces correctness bugs immediately.
- It creates a stable seam for later service extraction.
- It does not change the threat/risk core algorithms.

### Phase 1: Introduce application services

Status: completed on `architecture-review`.

Target modules:
- `src/app/analysis_service.py`
- `src/app/knowledge_service.py`

Scope:
- Move workflow orchestration out of `src/cli/main.py` and `src/ui/actions.py`.
- Replace subprocess-style UI orchestration with direct Python calls.
- Standardize success/error/result contracts across CLI and UI.

Deliverables:
- `AnalysisService.validate_model(model_path)`
- `AnalysisService.load_graph(model_path, clear_graph)`
- `AnalysisService.generate_threats(model_path, enrich)`
- `AnalysisService.score_risks(threat_path)`
- `AnalysisService.rebuild(model_path, clear_graph, enrich)`
- `KnowledgeService.sync(...)`

Delivered in this phase:
- Added shared application services in `src/app/analysis_service.py` and `src/app/knowledge_service.py`.
- Switched CLI analysis and sync commands to the shared services.
- Switched UI rebuild and sync actions to the same shared services.
- Removed the default UI rebuild dependency on subprocess execution and `stdout` parsing.
- Left query orchestration in the existing agent workflow; a dedicated `QueryService` was deferred because the current router/executor/composer split already provides a clear boundary.

Primary tests:
- CLI contract tests
- UI action tests
- rebuild workflow tests

### Phase 2: Centralize graph query ownership

Status: completed on `architecture-review`.

Problem:
- The agent router currently chooses concrete Cypher text directly.
- The graph layer already owns equivalent queries.

Scope:
- Replace raw Cypher strings in the router with stable query IDs.
- Add a `GraphQueryCatalog` or extend `GraphQueries` with a dispatch method.
- Make the tool layer execute graph queries by query ID plus params.

Deliverables:
- `graph_intent -> query_id` mapping in the router
- `query_graph(query_id, params)` tool contract
- one source of truth for trust-boundary, dependency, and exposure queries

Delivered in this phase:
- Added stable graph query IDs and dispatch in `src/graph/graph_queries.py`.
- Migrated the agent router to emit query IDs instead of raw Cypher.
- Migrated the agent tool path to execute named graph queries through the graph layer.
- Added router and graph-dispatch regression tests to keep the contract stable.

Primary tests:
- agent workflow tests
- graph query tests
- NLP golden suites

### Phase 3: Make threat generation dependency-driven

Status: completed on `architecture-review`.

Problem:
- Threat generation eagerly builds a full graph snapshot for every run.
- New heuristics require edits to a central snapshot builder.

Scope:
- Let each materializer declare the graph views it depends on.
- Resolve those views lazily and memoize them per run.
- Preserve deterministic ordering and output shape.

Deliverables:
- materializer dependency declaration API
- snapshot resolver with per-run cache
- threat-generation benchmark covering query count and runtime stability

Delivered in this phase:
- Added declared snapshot dependencies to Python materializers and inferred them for the generic TOML materializer.
- Added a lazy, cached snapshot resolver in `src/analysis/snapshot_resolver.py`.
- Migrated threat generation to use the resolver while preserving deterministic output behavior.
- Added resolver regression tests, including a check that the build path only hydrates declared graph views.

Primary tests:
- threat generation suite
- graph loader/query tests
- performance smoke benchmark

### Phase 4: Remove default-global repository and index access

Status: completed on `architecture-review`.

Problem:
- `ProjectPaths.default()` and `TechniqueIndex.get()` still behave like hidden globals.
- Long-lived sessions can serve stale technique data after sync.

Scope:
- Inject `ProjectPaths`, repositories, and technique indexes explicitly.
- Key or invalidate any remaining caches by backing store and sync version.

Deliverables:
- no required singleton access in runtime paths
- sync invalidates active technique index cleanly
- long-lived UI and agent processes reload knowledge safely

Delivered in this phase:
- Added an explicit `KnowledgeProvider` for refreshable knowledge-store and index access.
- Migrated long-lived runtime paths in the agent and analysis layers off `TechniqueIndex.get()`.
- Invalidated both provider-backed and legacy context-backed technique index state on sync.
- Added regression tests for provider refresh, injected knowledge behavior, and sync invalidation.

Primary tests:
- knowledge sync tests
- UI data access tests
- agent tool tests

### Phase 5: Add operational artifacts and manifests

Status: completed on `architecture-review`.

Scope:
- Record a manifest for each analysis run with model path, model id, output paths, and timestamps.
- Use manifests instead of filename guessing for active artifacts.
- Attach manifest metadata to observability traces.

Why later:
- The new session layer already improves correctness.
- Manifests are more valuable once services own orchestration.

Delivered in this phase:
- Added persisted analysis run manifests under `models/outputs/manifests/`.
- Recorded manifests from the analysis service and kept the active manifest in session state.
- Switched report loading to prefer manifest-backed artifact paths before filesystem discovery.
- Attached active manifest metadata to local observability trace events.

### Implemented order

1. Finish Phase 0 cleanup around session-aware path ownership.
2. Extract `AnalysisService` and move UI rebuild off subprocess execution.
3. Centralize graph query ownership behind query IDs.
4. Convert threat generation to lazy dependency resolution.
5. Remove runtime singleton defaults and add artifact manifests.

### Success metrics

- No UI code needs to parse CLI `stdout`.
- Agent graph queries use one canonical query source.
- Changing the active model clears stale artifacts automatically.
- Sync invalidates stale technique index state.
- Threat generation query count scales with heuristic dependencies, not the whole catalog.
- Threat and risk artifact resolution prefers the active manifest before filesystem discovery.
