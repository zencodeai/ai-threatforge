## Architecture Refactor Plan

This plan turns the current architecture review into an implementation roadmap with low-risk sequencing. The goal is to improve correctness and extensibility without destabilizing the deterministic analysis core.

### Guiding rules

1. Keep threat generation, risk scoring, and query answers deterministic.
2. Prefer new service boundaries over broad rewrites in place.
3. Move shared concerns behind typed APIs before changing behavior.
4. Add regression tests before replacing an existing entry point.

### Phase 0: Low-risk groundwork

Status: partially implemented on `architecture-review`.

Completed:
- Added a shared session store used by both CLI and UI.
- Persisted active model and artifact paths across CLI calls and UI sessions.
- Made report loading prefer the session artifact before falling back to discovery.
- Added focused regression tests for session persistence and CLI/UI resolution.

Remaining low-risk tasks:
- Replace lexicographic artifact fallback with mtime or manifest-based resolution.
- Move more default-path lookups off module globals and onto injected `ProjectPaths`.
- Add session-aware integration tests for the Streamlit app shell.

Why first:
- This reduces correctness bugs immediately.
- It creates a stable seam for later service extraction.
- It does not change the threat/risk core algorithms.

### Phase 1: Introduce application services

Target modules:
- `src/app/analysis_service.py`
- `src/app/knowledge_service.py`
- `src/app/query_service.py`

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
- `QueryService.answer(question, session=...)`

Order:
1. Extract thin wrappers around existing library calls.
2. Switch CLI to service calls.
3. Switch UI actions to the same service calls.
4. Remove `stdout` parsing from UI rebuild flow.

Primary tests:
- CLI contract tests
- UI action tests
- rebuild workflow tests

### Phase 2: Centralize graph query ownership

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

Order:
1. Add query IDs without removing current query methods.
2. Migrate agent graph queries to IDs.
3. Remove duplicated Cypher from the router.

Primary tests:
- agent workflow tests
- graph query tests
- NLP golden suites

### Phase 3: Make threat generation dependency-driven

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

Order:
1. Add dependency metadata to materializers.
2. Wrap existing snapshot calls behind a resolver.
3. Switch one or two heuristics first.
4. Migrate the full catalog after tests are stable.

Primary tests:
- threat generation suite
- graph loader/query tests
- performance smoke benchmark

### Phase 4: Remove default-global repository and index access

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

Order:
1. Introduce constructor injection where globals are used most heavily.
2. Replace hidden globals in knowledge and UI layers.
3. Remove compatibility singleton access last.

Primary tests:
- knowledge sync tests
- UI data access tests
- agent tool tests

### Phase 5: Add operational artifacts and manifests

Scope:
- Record a manifest for each analysis run with model path, model id, output paths, and timestamps.
- Use manifests instead of filename guessing for active artifacts.
- Attach manifest metadata to observability traces.

Why later:
- The new session layer already improves correctness.
- Manifests are more valuable once services own orchestration.

### Suggested implementation order

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
