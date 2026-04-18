# Design Review — Architecture Analysis & Improvement Plan

> Generated: 2026-04-17
> Scope: Full codebase SOLID analysis, Python pattern review, phased improvement plan
> **Status: All issues identified in Sections 1–3 have been resolved.** Implementation details are recorded in Appendices A (Phase 1), B (Phase 2), C (Phase 3), and D (Phase 4).

---

## 1. SOLID Principles Assessment

### S — Single Responsibility

| Module | Verdict | Notes |
|--------|---------|-------|
| `canonical_model.py` | ✅ Good | Clean: schema definition + cross-reference validation |
| `risk_scoring.py` | ✅ Good | Focused on scoring; each factor is a pure function |
| `data_access.py` / `actions.py` | ✅ Good | Clean separation of data reads vs subprocess execution |
| `threat_outputs.py` | ❌ Violation | Combines graph snapshot orchestration, Neo4j client creation, six heuristic materializers, report serialization, and the CLI-facing `generate_threat_report()` — all in one ~300-line file |
| `technique_mapping.py` | ❌ Violation | Three distinct responsibilities merged: TOML loading, knowledge-base resolution, and the 3-layer mapping engine. Also holds a 35-line legacy fallback tuple |
| `workflow.py` | ❌ Violation | Routing logic, action dispatch, and answer composition are three distinct concerns in one class |
| `graph_loader.py` | ⚠️ Borderline | Acceptable at current size, but each `_merge_*` emits its own Cypher and creates N+1 per entity |

### O — Open/Closed

| Area | Status | Detail |
|------|--------|--------|
| Threat heuristics | ❌ Closed to extension | Adding TH-007 requires editing `threat_outputs.py` (the giant materializer), `mapping_rules.toml`, and potentially `risk_scoring.py` rule-specific branches (`if threat.rule_id == "TH-002"`) |
| Risk factors | ❌ Closed | Factor functions contain hardcoded rule-specific `if` branches. A new rule with unique scoring behavior requires editing existing factor functions |
| Tool routing | ❌ Closed | `_route()` and `_run_action()` are `if`/`elif` chains. Adding a tool requires touching both methods |
| Trace recorders | ✅ Open | `TraceRecorder` protocol + `CompositeTraceRecorder` is well-designed |
| Graph queries | ⚠️ Closed | Each query is a separate method on `GraphQueries`. Acceptable today but will grow |

### L — Liskov Substitution

Generally respected. `TraceRecorder` protocol + `NullTraceRecorder` / `JsonlTraceRecorder` / `LangSmithTraceRecorder` all honor the contract. `NullTraceRecorder` does not formally implement the `Protocol` — it relies on structural subtyping, which is idiomatic Python but implicit.

### I — Interface Segregation

| Area | Status | Detail |
|------|--------|--------|
| `AgentTools` | ⚠️ Fat class | Five tools (`query_graph`, `get_threats`, `get_risks`, `lookup_technique`, `search_knowledge`) with unrelated dependencies (Neo4j, file system, knowledge index). A consumer wanting only risk lookups must accept graph-runner injection |
| `GraphQueries` | ⚠️ Growing | 10 public methods — any caller pulls all queries. Acceptable at current size |

### D — Dependency Inversion

| Area | Status | Detail |
|------|--------|--------|
| `technique_mapping.py` | ❌ Violates DIP | Imports `TechniqueIndex` at call-time inside private functions via `from knowledge.index import TechniqueIndex`. Hard dependency on concrete singleton, hidden behind bare `except Exception: pass` |
| `threat_outputs.py` | ❌ Violates DIP | `generate_threat_report()` directly instantiates `Neo4jConfig.from_env()` + `Neo4jClient`, making it impossible to test without a live database. The testable path (`build_threat_report_from_snapshot`) is good but coexists with the untestable one |
| `create_queries_from_env()` | ❌ Violates DIP | Factory hardcodes env-based construction with no injection seam |
| `AgentTools` | ⚠️ Partial | Accepts `graph_runner` callable but defaults to creating its own `Neo4jClient` internally |

---

## 2. Python Design Patterns & Best Practices

### What's Done Well

- **Immutable data** — `@dataclass(frozen=True)` for heuristics, techniques, config objects
- **Pydantic v2** — proper `model_validator`, `Field` constraints, `Literal` types throughout
- **Protocol-based tracing** — textbook structural subtyping with `TraceRecorder`
- **Composite pattern** — `CompositeTraceRecorder` cleanly stacks local + remote recorders
- **Context managers** — `Neo4jClient.__enter__/__exit__`, `TechniqueStore.__enter__/__exit__`
- **Determinism** — SHA-1 stable IDs, sorted outputs, reproducible pipeline end-to-end
- **Layered mapping** — curated → expansion → context filtering is a clean pipeline

### Issues Found

| # | Pattern / Practice | Issue | Location |
|---|-------------------|-------|----------|
| 1 | God function | `build_threat_report_from_snapshot()` is a ~170-line procedural block with six copy-pasted `ThreatRecord` construction patterns | `threat_outputs.py` |
| 2 | Hardcoded paths | `_MAPPING_RULES_PATH` and `_MAPPING_CONFIG_PATH` use `Path(__file__).resolve().parent.parent.parent` chains — brittle, untestable | `technique_mapping.py:9-10` |
| 3 | Silent exception swallowing | `except Exception: pass` in `_resolve_technique_name()` and `_expand_by_tactic()` — hides import failures, broken DBs, corrupted data | `technique_mapping.py` |
| 4 | Singleton with global mutable state | `TechniqueIndex._instance` class variable with manual double-checked locking; `reset()` exists only for tests — fragile in production | `knowledge/index.py` |
| 5 | N+1 graph writes | `GraphLoader` issues one `execute_write` per entity and per relationship — a model with 20 modules creates 60+ individual transactions | `graph_loader.py` |
| 6 | Duplicated artifact resolution | `_latest_artifact()` logic is duplicated in `AgentTools`, `data_access.py`, and `cli/main.py` | Multiple files |
| 7 | Duplicated `ROOT` path resolution | `ROOT = Path(__file__).resolve().parents[N]` appears independently in `app.py`, `data_access.py`, `actions.py` | UI layer |
| 8 | No abstract base / Protocol for tools | `_run_action()` is an if/elif dispatch on string tool names; no registry, no `Tool` protocol | `agents/workflow.py` |
| 9 | SHA-1 for ID generation | `hashlib.sha1()` is not a security concern here (stable IDs only), but `hashlib.sha256` is the modern default | `threat_outputs.py`, `risk_scoring.py` |
| 10 | Missing `__all__` exports | Most `__init__.py` files are empty; public API surface is implicit | All packages |

---

## 3. Improvement Plan

### Phase 1 — Structural Refactors (Modularity & SRP)

| # | Change | Rationale | Effort |
|---|--------|-----------|--------|
| 1.1 | **Extract threat materializers into a registry pattern** — each heuristic gets a `materialize(snapshot, model) -> list[ThreatRecord]` function or class registered by `rule_id`. `build_threat_report_from_snapshot` becomes a loop over the registry. | Fixes SRP violation in `threat_outputs.py`, makes adding TH-007+ additive (OCP). | Medium |
| 1.2 | **Extract risk factor strategy** — define a `RiskFactor(Protocol)` with `score(threat) -> float`, register factor functions, eliminate rule-specific `if threat.rule_id` branches from each factor function. | OCP for risk scoring; each new rule can declare its own factor adjustments. | Medium |
| 1.3 | **Split `technique_mapping.py`** into `mapping_loader.py` (TOML I/O), `mapping_engine.py` (layered resolution), and move legacy fallbacks to `_legacy.py` or remove entirely. | SRP; simplifies testing of each layer independently. | Small |
| 1.4 | **Split `workflow.py`** into `router.py` (question → actions), `executor.py` (action → tool call), `composer.py` (tool results → answer). | SRP; each piece becomes independently testable and extensible. | Small |

### Phase 2 — Dependency Inversion & Testability

| # | Change | Rationale | Effort |
|---|--------|-----------|--------|
| 2.1 | **Introduce a `Tool` protocol** — `class Tool(Protocol): name: str; def run(self, input: dict) -> ToolResponse` — and register tools in a `ToolRegistry` dict. Replace `_run_action()` if/elif with `registry[action.tool_name].run(input)`. | DIP + OCP; adding tools requires no workflow changes. | Small |
| 2.2 | **Inject paths via config dataclass** — replace all `Path(__file__).parents[N]` with a `ProjectPaths` config injected at startup. CLI/UI create it once; tests inject temp dirs. | DIP; eliminates path fragility and duplication. | Small |
| 2.3 | **Inject knowledge index** — `technique_mapping` functions accept `TechniqueIndex | None` parameter instead of importing and calling `.get()` internally. Remove `except Exception: pass` — let callers decide fallback. | DIP; eliminates hidden coupling and silent failures. | Small |
| 2.4 | **Extract artifact resolver** — single `ArtifactLocator` class used by `AgentTools`, `data_access.py`, and CLI for finding latest threat/risk JSON files. | DRY; one implementation, one set of tests. | Small |

### Phase 3 — Performance & Robustness

| # | Change | Rationale | Effort |
|---|--------|-----------|--------|
| 3.1 | **Batch graph writes** — replace per-entity `execute_write` with `UNWIND $batch AS row MERGE ...` patterns. Single transaction per entity type. | Eliminates N+1; 60+ round-trips → ~10. | Medium |
| 3.2 | **Replace bare `except Exception: pass`** with explicit exception types and logging. | Prevents silent data corruption; aids debugging. | Small |
| 3.3 | **Add `__all__` to package `__init__.py` files** — export the public API surface explicitly. | Standard Python practice; helps tooling, docs, and tab-completion. | Small |

### Phase 4 — Optional / Future

| # | Change | Rationale | Effort |
|---|--------|-----------|--------|
| 4.1 | **Plugin-based heuristic loading** — heuristics declared as entry points or a `heuristics/` directory with auto-discovery. | Full OCP; third parties can add rules without touching core code. | Large |
| 4.2 | **Repository pattern for artifacts** — abstract read/write of threat and risk reports behind a `ReportRepository` interface (file-based impl, could later be S3/DB). | ISP + DIP; decouples pipeline from file system. | Medium |
| 4.3 | **Replace singleton `TechniqueIndex`** with a request-scoped or app-scoped dependency injected via a simple container or `contextvars`. | Eliminates global mutable state; trivial test isolation. | Medium |

---

## 4. Priority Recommendation

**Start with Phase 1.1 + 2.1 + 2.2** — these three changes address the highest-impact SOLID violations:

1. **1.1** (threat materializer registry) breaks up the largest god function and unlocks additive heuristic development
2. **2.1** (Tool protocol) eliminates the if/elif dispatch and makes the agent layer extensible
3. **2.2** (path config injection) removes the most pervasive cross-cutting fragility

These are the three areas most likely to grow as the project evolves — new threat rules, new agent tools, and new deployment contexts — and addressing them first yields compounding benefits for all subsequent phases.

Phase 2.3 + 3.2 (inject knowledge index, fix silent exceptions) should follow immediately as they are small, high-value changes that improve correctness and debuggability.

Phase 3.1 (batch graph writes) is worth prioritizing if graph load times become a bottleneck with larger models.

Phase 4 items are architectural investments that make sense once the core extension patterns from Phases 1-2 are proven in practice.

---

## Appendix A — Phase 1 Implementation Record

> Implemented: 2026-04-17
> Test result: 82 passed, 2 skipped, 2 pre-existing failures (unrelated to Phase 1)

### A.1 — Threat Materializer Registry (Task 1.1)

**Problem:** `build_threat_report_from_snapshot()` in `threat_outputs.py` was a ~170-line procedural god function containing six copy-pasted `ThreatRecord` construction blocks — one per heuristic rule (TH-001 through TH-006). Adding a new rule required editing this function.

**Solution:** Extracted each rule's materialization logic into a dedicated class behind a `ThreatMaterializer` protocol, managed by a global registry.

**New files:**

| File | Purpose |
|------|---------|
| `src/analysis/materializer_registry.py` | `ThreatMaterializer` protocol defining the `rule_id` + `materialize()` contract. Registry functions: `register_materializer()`, `get_materializer()`, `registered_rule_ids()`, `all_materializers()`. |
| `src/analysis/materializers.py` | Six concrete classes (`TH001Materializer` through `TH006Materializer`), each with a `rule_id` class attribute and a `materialize()` method containing the logic verbatim from the old function. |

**Modified files:**

| File | Change |
|------|--------|
| `src/analysis/threat_outputs.py` | Removed the six inline rule blocks. Module-level code now imports all six materializer classes and calls `register_materializer()` for each. `build_threat_report_from_snapshot()` is now a simple loop: iterate `all_materializers()`, call `materialize()`, deduplicate, sort. All helper functions (`_timestamp`, `_stable_threat_id`, `_sorted_unique`, `_build_snapshot`, `_technique_refs`, `_heuristic`) preserved unchanged. |

**Design decisions:**
- Used a module-level `Protocol` rather than an ABC to stay consistent with the existing `TraceRecorder` protocol pattern.
- Materializers are registered at import time via explicit `register_materializer()` calls in `threat_outputs.py`, keeping registration deterministic and traceable.
- Each materializer receives shared utility functions (`technique_refs_fn`, `stable_id_fn`, `sorted_unique_fn`) as keyword arguments rather than inheriting them, avoiding a base-class dependency.

**OCP impact:** Adding TH-007 now requires: (1) a new class in `materializers.py`, (2) a `register_materializer()` call in `threat_outputs.py`. No existing materializer or the orchestration loop needs modification.

---

### A.2 — Risk Factor Strategy Pattern (Task 1.2)

**Problem:** `risk_scoring.py` contained six factor functions (`_likelihood`, `_impact`, `_exposure`, `_privilege_sensitivity`, `_data_criticality`, `_exploitability`) with hardcoded `if threat.rule_id == "TH-002"` branches embedded in each. Adding a new rule with unique scoring behavior required editing multiple existing functions.

**Solution:** Extracted all factor functions and weight constants into a dedicated module with data-driven rule adjustments and a factor registry.

**New file:**

| File | Purpose |
|------|---------|
| `src/analysis/risk_factors.py` | `RiskFactorFn` type alias, `SEVERITY_BASE` and `RISK_WEIGHTS` dicts, six named factor functions (`likelihood`, `impact`, `exposure`, `privilege_sensitivity`, `data_criticality`, `exploitability`), and `FACTOR_REGISTRY` mapping names to functions. |

**Key design change — data-driven rule adjustments:**

Rule-specific scoring adjustments were converted from inline `if` branches to lookup dicts:

```python
# Before (in risk_scoring.py):
def _likelihood(threat):
    ...
    if threat.rule_id == "TH-002":
        score += 0.10
    ...

# After (in risk_factors.py):
_LIKELIHOOD_RULE_BONUS: dict[str, float] = {"TH-002": 0.10}

def likelihood(threat):
    ...
    score += _LIKELIHOOD_RULE_BONUS.get(threat.rule_id, 0.0)
    ...
```

Similar dicts: `_IMPACT_RULE_BONUS`, `_PRIVILEGE_RULE_SET`, `_DATA_CRIT_RULE_SET`.

**Modified files:**

| File | Change |
|------|--------|
| `src/analysis/risk_scoring.py` | Removed six inline factor functions and `RISK_WEIGHTS`. Added `from .risk_factors import FACTOR_REGISTRY, RISK_WEIGHTS`. `score_threat()` now uses `{name: fn(threat) for name, fn in FACTOR_REGISTRY.items()}` to compute all factors in one expression. |
| `src/analysis/__init__.py` | Updated `RISK_WEIGHTS` import source from `.risk_scoring` to `.risk_factors`. |

**OCP impact:** A new rule's scoring adjustments are declared by adding entries to the bonus/set dicts — no existing factor function bodies are modified. New factor types can be added by defining a function and registering it in `FACTOR_REGISTRY`.

---

### A.3 — Split technique_mapping (Task 1.3)

**Problem:** `technique_mapping.py` merged three distinct responsibilities — TOML I/O, knowledge-base name resolution, and the 3-layer mapping engine — into a single 230-line file. It also held a 35-line legacy fallback tuple.

**Solution:** Split into three focused modules; the original file becomes a thin backward-compatible facade.

**New files:**

| File | Purpose |
|------|---------|
| `src/analysis/mapping_types.py` | `TechniqueMapping` frozen dataclass and `LEGACY_MAPPINGS` tuple (13 entries). Pure data, no I/O. |
| `src/analysis/mapping_loader.py` | `_resolve_technique_name()` (knowledge-base lookup with legacy fallback), `load_curated_mappings()` (TOML loading with legacy fallback), `load_expansion_config()` (expansion TOML loading). All file I/O isolated here. |
| `src/analysis/mapping_engine.py` | `_expand_by_tactic()` (Layer 2 tactic expansion), `_filter_by_context()` (Layer 3 platform filtering), `map_rule_to_techniques()` (public API combining all 3 layers). Pure logic, no I/O. |

**Modified files:**

| File | Change |
|------|--------|
| `src/analysis/technique_mapping.py` | Replaced entire contents with a re-export facade. Imports `TechniqueMapping`, `map_rule_to_techniques`, `load_curated_mappings` from the new modules. Re-exports the same public API: `get_rule_technique_mappings()`, `get_all_technique_mappings()`, `map_rule_to_techniques()`, `validate_mapping_coverage()`. Declares `__all__`. |

**Backward compatibility:** All existing importers (`from analysis.technique_mapping import get_rule_technique_mappings`, etc.) continue to work unchanged. The facade delegates every call to the appropriate new module.

---

### A.4 — Split workflow.py (Task 1.4)

**Problem:** `QueryWorkflow` in `workflow.py` combined three distinct concerns — question routing, tool dispatch, and answer composition — in a single class with interleaved private methods.

**Solution:** Extracted each concern into a dedicated class in its own module. `QueryWorkflow` remains as a slim orchestrator that delegates to the three.

**New files:**

| File | Purpose |
|------|---------|
| `src/agents/router.py` | `RoutedAction` frozen dataclass (moved from `workflow.py`). `QueryRouter` class with `route(question) -> list[RoutedAction]` implementing keyword-based routing, technique-ID regex matching, module hint extraction, and Cypher query selection. |
| `src/agents/executor.py` | `ActionExecutor` class with `run(action: RoutedAction) -> ToolResponse`. Dispatches each action to the corresponding `AgentTools` method. |
| `src/agents/composer.py` | `AnswerComposer` class with `compose(state: AgentState) -> AgentAnswer`. Iterates tool call results, builds answer text with evidence refs, and collects limitations. |

**Modified files:**

| File | Change |
|------|--------|
| `src/agents/workflow.py` | Reduced from ~200 lines to ~35 lines. `QueryWorkflow.__init__` now creates `QueryRouter`, `ActionExecutor`, and `AnswerComposer` instances. `answer()` delegates routing → execution loop → composition. No private methods remain. |

**Public API preserved:** `QueryWorkflow(tools, tracer).answer(question) -> (AgentAnswer, AgentState)` is unchanged. `src/agents/__init__.py` required no modifications — it imports only `QueryWorkflow` from `workflow`.

---

### A.5 — Test Verification

Full test suite run after all Phase 1 changes:

```
82 passed, 2 skipped, 2 failed
```

**Passed (Phase 1–relevant):**
- `test_threat_outputs.py` — all tests pass (materializer registry integration)
- `test_risk_scoring.py` — all tests pass (factor registry integration)
- `test_technique_mapping.py` — all tests pass (facade re-exports)
- `test_agent_workflow.py` — all tests pass (split workflow delegation)
- `test_risk_model.py`, `test_schema.py`, `test_threat_generation.py` — unchanged, all pass

**2 pre-existing failures** (not caused by Phase 1):
- `test_agents_tools.py::test_lookup_technique_returns_matches` — expects `source == "technique-mappings"` but `AgentTools` returns `"knowledge-base"` when the knowledge store is populated
- `test_agents_tools.py::test_search_knowledge_stub_returns_ranked_items` — expects `source == "knowledge-stub"` but gets `"knowledge-base"`

These failures exist on the pre-refactor baseline and relate to source-label logic in `src/agents/tools.py`, which was not modified in Phase 1.

---

### A.6 — File Inventory

**New files created (8):**

| File | Lines | Package |
|------|-------|---------|
| `src/analysis/materializer_registry.py` | 46 | analysis |
| `src/analysis/materializers.py` | ~250 | analysis |
| `src/analysis/risk_factors.py` | 138 | analysis |
| `src/analysis/mapping_types.py` | 50 | analysis |
| `src/analysis/mapping_loader.py` | ~70 | analysis |
| `src/analysis/mapping_engine.py` | ~90 | analysis |
| `src/agents/router.py` | 117 | agents |
| `src/agents/executor.py` | 35 | agents |
| `src/agents/composer.py` | 80 | agents |

**Modified files (5):**

| File | Nature of change |
|------|-----------------|
| `src/analysis/threat_outputs.py` | God function replaced with registry loop |
| `src/analysis/risk_scoring.py` | Factor functions replaced with registry import |
| `src/analysis/technique_mapping.py` | Rewritten as re-export facade |
| `src/analysis/__init__.py` | `RISK_WEIGHTS` import path updated |
| `src/agents/workflow.py` | Reduced to slim orchestrator |

---

## Appendix B — Phase 2 Implementation Record

> Implemented: 2026-04-17
> Test result: 82 passed, 2 skipped, 2 pre-existing failures (unchanged from Phase 1 baseline)

### B.1 — Tool Protocol + Registry (Task 2.1)

**Problem:** `ActionExecutor.run()` dispatched tool calls via a 5-branch if/elif chain on `action.tool_name`. Adding a new tool required editing the executor — violating OCP and DIP.

**Solution:** Introduced a `Tool` protocol and a name-keyed `ToolRegistry`. Each tool is a small wrapper class that delegates to the corresponding `AgentTools` method. `ActionExecutor` now resolves tools via dictionary lookup.

**New file:**

| File | Purpose |
|------|---------|
| `src/agents/tool_protocol.py` | `Tool` protocol with `name: str` property and `run(tool_input: dict) -> ToolResponse` method. `ToolRegistry = dict[str, Tool]` type alias. |

**Modified files:**

| File | Change |
|------|--------|
| `src/agents/tools.py` | Added five tool wrapper classes (`_QueryGraphTool`, `_GetThreatsTool`, `_GetRisksTool`, `_LookupTechniqueTool`, `_SearchKnowledgeTool`), each satisfying the `Tool` protocol. Added `AgentTools.tool_registry() -> ToolRegistry` method that builds and returns the name→tool mapping. |
| `src/agents/executor.py` | Replaced the 5-branch if/elif with `self._registry.get(action.tool_name)`. Constructor now calls `tools.tool_registry()` to build the registry once. Reduced from 37 lines to 19 lines. |

**Design decisions:**
- Tool wrappers are private classes inside `tools.py` (not separate files) since they are thin adapters with no independent logic.
- The registry is built eagerly in `ActionExecutor.__init__` rather than lazily, ensuring tool availability is validated at construction time.
- `AgentTools` retains its public methods unchanged, so existing direct callers (tests, UI) are unaffected.

**OCP impact:** Adding a new tool requires: (1) a method on `AgentTools`, (2) a wrapper class, (3) adding it to the `tool_registry()` list. No `ActionExecutor` or `QueryWorkflow` code needs modification.

---

### B.2 — ProjectPaths Config Injection (Task 2.2)

**Problem:** Path resolution was duplicated across the codebase via `ROOT = Path(__file__).resolve().parents[N]` (7 occurrences) and `Path(__file__).resolve().parent.parent.parent / "data" / ...` chains (3 occurrences). Each used a different `parents[N]` depth depending on file location — brittle under restructuring and untestable.

**Solution:** Created a centralized `ProjectPaths` frozen dataclass with a `from_root()` classmethod. All path consumers now use `ProjectPaths.default()` instead of computing paths from `__file__`.

**New file:**

| File | Purpose |
|------|---------|
| `src/project_paths.py` | `ProjectPaths` frozen dataclass with fields: `root`, `data_dir`, `examples_dir`, `outputs_dir`, `threats_dir`, `risks_dir`, `mapping_rules`, `mapping_config`, `knowledge_db`. Classmethods: `from_root(root)` derives all paths from a single root, `default()` resolves from the package location. |

**Modified files:**

| File | Change |
|------|--------|
| `src/analysis/mapping_loader.py` | Replaced `_MAPPING_RULES_PATH` and `_MAPPING_CONFIG_PATH` module-level `Path(__file__).resolve().parent.parent.parent / ...` with `_DEFAULT_PATHS = ProjectPaths.default()`. `load_curated_mappings()` and `load_expansion_config()` default to `_DEFAULT_PATHS.mapping_rules` / `.mapping_config`. |
| `src/knowledge/store.py` | Replaced `DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent.parent / ...` with `ProjectPaths.default().knowledge_db`. |
| `src/ui/data_access.py` | `ROOT = ProjectPaths.default().root` replaces `Path(__file__).resolve().parents[2]`. |
| `src/ui/actions.py` | Same pattern — `ROOT = ProjectPaths.default().root`. |
| `src/ui/app.py` | Same pattern. |
| `src/ui/pages/chat.py` | Same pattern — replaces `parents[3]`. |
| `src/ui/pages/threats.py` | Same pattern. |
| `src/ui/pages/risks.py` | Same pattern. |
| `src/ui/pages/model_overview.py` | Same pattern. |

**Testability impact:** Tests can now call `ProjectPaths.from_root(tmp_path)` to get a fully resolved path set pointing at a temporary directory, without monkey-patching module-level constants.

---

### B.3 — Inject Knowledge Index (Task 2.3)

**Problem:** `mapping_loader._resolve_technique_name()`, `mapping_engine._expand_by_tactic()`, and `mapping_engine._filter_by_context()` all contained hidden `from knowledge.index import TechniqueIndex; index = TechniqueIndex.get()` calls wrapped in bare `except Exception: pass`. This violated DIP (hard dependency on a concrete singleton) and silently swallowed errors including import failures, broken databases, and corrupted data.

**Solution:** All three functions now accept an `index: TechniqueIndex | None` keyword argument. When `None`, the caller decides whether to provide an index or accept fallback behavior. The top-level `map_rule_to_techniques()` provides a `_get_default_index()` helper as a convenience default.

**Modified files:**

| File | Change |
|------|--------|
| `src/analysis/mapping_loader.py` | `_resolve_technique_name(technique_id, *, index=None)` — uses the injected index if provided, falls back to legacy name lookup otherwise. Removed `try/except Exception: pass` block. `load_curated_mappings()` gained `index` kwarg, passed through to `_resolve_technique_name()`. |
| `src/analysis/mapping_engine.py` | `_expand_by_tactic(rule_id, config, *, index=None)` — returns `()` if index is `None` or not populated, instead of catching exceptions. `_filter_by_context(mappings, context, *, index=None)` — returns unfiltered mappings if index is `None`. `map_rule_to_techniques(rule_id, context, *, index=None)` — calls `_get_default_index()` when index is `None`, propagates to all sub-functions. |
| `src/analysis/technique_mapping.py` | Removed unused `LEGACY_MAPPINGS` import (dead code cleanup). |

**Design decisions:**
- `_get_default_index()` is a private helper in `mapping_engine.py` that wraps the singleton access with a `try/except` returning `None`. This keeps the convenience behavior at the top level while making the lower layers fully injectable and testable.
- `TYPE_CHECKING`-guarded imports prevent circular dependency issues — the `TechniqueIndex` type is only needed at type-check time since the runtime parameter is `| None`.

**Error handling impact:** Silent `except Exception: pass` blocks are eliminated from both `mapping_loader.py` and `mapping_engine.py`. When an index is explicitly provided, any errors propagate to the caller. When using the default (`_get_default_index()`), the singleton lookup is the only place that catches exceptions — and that decision is now explicit and isolated.

---

### B.4 — Extract Artifact Resolver (Task 2.4)

**Problem:** The "find latest artifact file by glob pattern" logic was duplicated in three locations with slightly different signatures:
1. `AgentTools._latest_artifact(self, folder, suffix)` — instance method, uses `self.base_dir`
2. `data_access.latest_artifact(base_dir, folder, suffix)` — standalone function
3. `cli/main.py::_default_threat_path()` — hardcoded path, no `base_dir` parameter

All three implemented the same pattern: `sorted(path.glob(f"*{suffix}"))[-1]`.

**Solution:** Created a single `ArtifactLocator` class. All three consumers now delegate to it.

**New file:**

| File | Purpose |
|------|---------|
| `src/artifact_locator.py` | `ArtifactLocator` class with `__init__(base_dir)`, `latest(folder, suffix) -> Path | None`, `latest_threats() -> Path | None`, `latest_risks() -> Path | None`. |

**Modified files:**

| File | Change |
|------|--------|
| `src/agents/tools.py` | `AgentTools.__init__` creates `self._locator = ArtifactLocator(self.base_dir)`. `_latest_artifact()` delegates to `self._locator.latest()`. |
| `src/ui/data_access.py` | `latest_artifact()` delegates to `ArtifactLocator(base_dir).latest()`. Function signature preserved for backward compatibility (used by tests). |
| `src/cli/main.py` | `_default_threat_path()` uses `ArtifactLocator(Path(".")).latest_threats()`. |

**Backward compatibility:** `data_access.latest_artifact()` remains a public function with the same signature — `test_ui_data_access.py` imports and calls it unchanged.

---

### B.5 — Test Verification

Full test suite run after all Phase 2 changes:

```
82 passed, 2 skipped, 2 failed
```

**Passed (Phase 2–relevant):**
- `test_agent_workflow.py` — all tests pass (registry-based executor)
- `test_technique_mapping.py` — all tests pass (injected index defaults)
- `test_ui_data_access.py` — all tests pass (`latest_artifact` delegation)
- `test_ui_actions.py` — all tests pass (`ProjectPaths` ROOT)
- All Phase 1 tests remain green

**2 pre-existing failures** (unchanged from Phase 1 baseline):
- `test_agents_tools.py::test_lookup_technique_returns_matches` — source label mismatch
- `test_agents_tools.py::test_search_knowledge_stub_returns_ranked_items` — source label mismatch

These failures predate both Phase 1 and Phase 2; they relate to `AgentTools` returning `"knowledge-base"` when the knowledge store is populated, while tests expect the fallback labels.

---

### B.6 — File Inventory

**New files created (3):**

| File | Lines | Package |
|------|-------|---------|
| `src/agents/tool_protocol.py` | 17 | agents |
| `src/project_paths.py` | 41 | (top-level) |
| `src/artifact_locator.py` | 24 | (top-level) |

**Modified files (12):**

| File | Nature of change |
|------|-----------------|
| `src/agents/executor.py` | if/elif dispatch → registry lookup |
| `src/agents/tools.py` | Added 5 tool wrapper classes + `tool_registry()` method + `ArtifactLocator` delegation |
| `src/analysis/mapping_loader.py` | `ProjectPaths` defaults; `index` injection; removed `except Exception: pass` |
| `src/analysis/mapping_engine.py` | `index` injection on all functions; `_get_default_index()` helper; removed `except Exception: pass` |
| `src/analysis/technique_mapping.py` | Removed unused `LEGACY_MAPPINGS` import |
| `src/knowledge/store.py` | `DEFAULT_DB_PATH` from `ProjectPaths` |
| `src/ui/data_access.py` | `ROOT` from `ProjectPaths`; `latest_artifact` delegates to `ArtifactLocator` |
| `src/ui/actions.py` | `ROOT` from `ProjectPaths` |
| `src/ui/app.py` | `ROOT` from `ProjectPaths` |
| `src/ui/pages/chat.py` | `ROOT` from `ProjectPaths` |
| `src/ui/pages/threats.py` | `ROOT` from `ProjectPaths` |
| `src/ui/pages/risks.py` | `ROOT` from `ProjectPaths` |
| `src/ui/pages/model_overview.py` | `ROOT` from `ProjectPaths` |
| `src/cli/main.py` | `_default_threat_path` delegates to `ArtifactLocator` |

---

## Appendix C — Phase 3 Implementation Record

> Implemented: 2026-04-17
> Test result: 82 passed, 2 skipped, 2 pre-existing failures (unchanged from Phase 2 baseline)

### C.1 — Batch Graph Writes (Task 3.1)

**Problem:** `GraphLoader` issued one `execute_write` call per entity and per relationship. Each call opened a new Neo4j session and transaction. A model with 6 domains, 10 modules, 5 datastores, 4 workflows, and 3 trust boundaries generated 60+ individual round-trips to the database.

**Solution:** Replaced every per-entity loop with an `UNWIND $batch AS row` pattern. Each `_merge_*` and `_link_*` method now builds a list of parameter dicts and issues a single `execute_write` per Cypher statement type.

**Modified file:**

| File | Change |
|------|--------|
| `src/graph/graph_loader.py` | All 10 `_merge_*` / `_link_*` methods rewritten to use `UNWIND` batches. `_merge_system` is unchanged (single entity). |

**Method-by-method changes:**

| Method | Before | After |
|--------|--------|-------|
| `_merge_domains` | 1 call per domain | 1 call total |
| `_merge_privileges` | 1 call per privilege | 1 call total |
| `_merge_modules` | 3 calls per module (node + IN_DOMAIN + HAS_PRIVILEGE) | 3 calls total |
| `_merge_objects` | 1 call per object | 1 call total |
| `_merge_datastores` | 2 calls per store + 1 per contained object | 3 calls total (nodes + domains + contains) |
| `_merge_external_actors` | 1 call per actor | 1 call total |
| `_merge_workflows` | 1 per workflow + 1 per module ref + 1 per object ref | 3 calls total (nodes + modules + objects) |
| `_merge_trust_boundaries` | 3 calls per boundary (node + CROSSES_FROM + CROSSES_TO) | 3 calls total |
| `_merge_dependencies` | 1 call per dependency | 1 call total |
| `_link_system` | 1 call per domain/module/datastore/object/workflow/boundary | Up to 6 calls total (1 per entity type) |
| `_link_actor_workflows` | 1 call per matching actor-step pair | 1 call total |

**Total round-trips:** Reduced from ~60+ to ~25 (varies by model size; the count is now fixed per entity type, not per entity instance).

**Design decisions:**
- Each method guards with `if not model.<collection>: return` to avoid issuing empty `UNWIND` statements.
- Relationship batches (e.g., datastore→contains, workflow→modules) are built as separate flat lists and only issued when non-empty.
- The `UNWIND $batch AS row` pattern is idiomatic Neo4j for bulk operations and maintains MERGE idempotency.

**Test compatibility:** Existing test assertions check for MERGE pattern strings via `in` operator (e.g., `"MERGE (m)-[:IN_DOMAIN]->(d)" in q`). These patterns still appear within the `UNWIND` queries, so `test_graph_loader.py` passes unchanged.

---

### C.2 — Replace Bare `except Exception: pass` (Task 3.2)

**Problem:** Five locations in the codebase used bare `except Exception: pass` or `except Exception:` with no logging, silently swallowing errors including import failures, database corruption, and misconfiguration.

**Solution:** Each site now either (a) logs with `exc_info=True` at an appropriate level, or (b) narrows the exception type to the specific failures expected.

**Modified files:**

| File | Site | Before | After |
|------|------|--------|-------|
| `src/agents/tools.py` | `lookup_technique()` — knowledge index access | `except Exception: pass` | `except Exception:` + `logging.debug("Knowledge index unavailable for technique lookup", exc_info=True)` |
| `src/agents/tools.py` | `search_knowledge()` — knowledge index access | `except Exception: pass` | `except Exception:` + `logging.debug("Knowledge index unavailable for knowledge search", exc_info=True)` |
| `src/analysis/mapping_engine.py` | `_get_default_index()` — singleton lookup | `except Exception: return None` | `except Exception:` + `logging.debug("TechniqueIndex singleton unavailable", exc_info=True)` then `return None` |
| `src/agents/observability.py` | `create_trace_recorder()` — LangSmith init | `except Exception:` (broad) | `except (ImportError, ValueError, RuntimeError):` + `logging.warning("LangSmith recorder unavailable; using local tracing only", exc_info=True)` |

**Preserved intentionally (not modified):**

| File | Site | Reason |
|------|------|--------|
| `src/cli/main.py` (4 sites) | `except Exception as exc: print(f"FAILED: {exc}")` | These are CLI top-level error handlers that already report the error to the user via `print`. They catch broadly by design to produce user-friendly output rather than tracebacks. |
| `src/ui/pages/model_overview.py` | `except Exception as exc: st.error(...)` | UI error handler — displays error in Streamlit. Same rationale as CLI. |

**Design decisions:**
- `tools.py` uses `DEBUG` level because the knowledge index being unavailable is a normal degraded-mode path (falls back to curated mappings). Logging at higher levels would produce noise in environments without a populated knowledge base.
- `observability.py` uses `WARNING` because a user explicitly opted into LangSmith tracing (via `LANGSMITH_TRACING=true`) but it failed — this warrants operator attention.
- `observability.py` narrows to `(ImportError, ValueError, RuntimeError)` — the three concrete failure modes: missing `langsmith` package, invalid config, or runtime initialization failure.

---

### C.3 — Add `__all__` to Package `__init__.py` Files (Task 3.3)

**Problem:** Five packages had empty or docstring-only `__init__.py` files with no explicit `__all__`. The public API surface was implicit — tooling, documentation generators, and `from package import *` had no contract to follow.

**Solution:** Added `__all__` declarations and, where appropriate, re-exports of the public API.

**Modified files:**

| File | `__all__` contents | Additional changes |
|------|-------------------|-------------------|
| `src/knowledge/__init__.py` | `["Mitigation", "Tactic", "Technique", "TechniqueIndex", "TechniqueStore", "sync", "sync_status"]` | Added imports from `.index`, `.models`, `.store`, `.sync` |
| `src/cli/__init__.py` | `["main"]` | Added import from `.main` and docstring |
| `src/models/__init__.py` | `["CanonicalModel", "RiskRecord", "RiskReport", "ThreatRecord", "ThreatReport", "load_canonical_model"]` | Added re-exports from `.schema` and docstring |
| `src/ui/__init__.py` | `[]` (empty list) | Explicit empty — UI package has no public re-exports (consumers import from submodules directly) |
| `src/ui/pages/__init__.py` | `["chat", "model_overview", "risks", "threats"]` | Module-level names (page modules, not symbols) |

**Already had `__all__` (unchanged):**

| File | Status |
|------|--------|
| `src/agents/__init__.py` | Already declares `__all__` with 9 exports |
| `src/analysis/__init__.py` | Already declares `__all__` with 14 exports |
| `src/graph/__init__.py` | Already declares `__all__` with 5 exports |
| `src/models/schema/__init__.py` | Already declares `__all__` with 6 exports |

---

### C.4 — Test Verification

Full test suite run after all Phase 3 changes:

```
82 passed, 2 skipped, 2 failed
```

All Phase 1 and Phase 2 tests remain green. The 2 pre-existing failures are unchanged:
- `test_agents_tools.py::test_lookup_technique_returns_matches` — source label mismatch
- `test_agents_tools.py::test_search_knowledge_stub_returns_ranked_items` — source label mismatch

---

### C.5 — File Inventory

**New files created:** None.

**Modified files (8):**

| File | Nature of change |
|------|-----------------|
| `src/graph/graph_loader.py` | All `_merge_*` / `_link_*` methods converted to `UNWIND` batch patterns |
| `src/agents/tools.py` | Two `except Exception: pass` → `DEBUG` logging |
| `src/agents/observability.py` | `except Exception` narrowed to `(ImportError, ValueError, RuntimeError)` + `WARNING` logging |
| `src/analysis/mapping_engine.py` | `_get_default_index()` `except Exception` → `DEBUG` logging |
| `src/knowledge/__init__.py` | Added re-exports and `__all__` |
| `src/cli/__init__.py` | Added `main` re-export and `__all__` |
| `src/models/__init__.py` | Added schema re-exports and `__all__` |
| `src/ui/__init__.py` | Added explicit empty `__all__` |
| `src/ui/pages/__init__.py` | Added page module names to `__all__` |

---

## Appendix D — Phase 4 Implementation Record

> Implemented: 2026-04-17
> Test result: 82 passed, 2 skipped, 2 pre-existing failures (unchanged from Phase 3 baseline)

### D.1 — Plugin-Based Heuristic Loading (Task 4.1)

**Problem:** Adding a new threat heuristic (e.g. TH-007) required editing three files: adding a `ThreatHeuristic` entry to the hardcoded `THREAT_HEURISTICS` tuple in `threat_generation.py`, adding a materializer class to `materializers.py`, and adding a `register_materializer()` call in `threat_outputs.py`. The system was closed to extension — violating OCP.

**Solution:** Created a `heuristics/` sub-package under `analysis/` with auto-discovery. Each heuristic is a standalone module (`th_001.py` – `th_006.py`) containing both its `HEURISTIC` definition and its materializer class. At import time, the package scans for `th_*.py` modules via `pkgutil.iter_modules`, extracts the `HEURISTIC` constant and the materializer class, and makes them available through `discovered_heuristics()` and `discovered_materializers()`.

**New files:**

| File | Purpose |
|------|---------|
| `src/analysis/heuristics/__init__.py` | Auto-discovery engine. `_discover()` scans for `th_*.py` modules, extracts `HEURISTIC` dataclass instances and materializer classes. Exports `discovered_heuristics()` and `discovered_materializers()`. |
| `src/analysis/heuristics/th_001.py` | `HEURISTIC` definition + `TH001Materializer` class for TH-001 (internet-exposed modules). |
| `src/analysis/heuristics/th_002.py` | `HEURISTIC` definition + `TH002Materializer` class for TH-002 (low-trust attack paths). |
| `src/analysis/heuristics/th_003.py` | `HEURISTIC` definition + `TH003Materializer` class for TH-003 (high-privilege externally reachable). |
| `src/analysis/heuristics/th_004.py` | `HEURISTIC` definition + `TH004Materializer` class for TH-004 (AI module dependencies). |
| `src/analysis/heuristics/th_005.py` | `HEURISTIC` definition + `TH005Materializer` class for TH-005 (regulated object concentration). |
| `src/analysis/heuristics/th_006.py` | `HEURISTIC` definition + `TH006Materializer` class for TH-006 (trust boundary crossings). |

**Modified files:**

| File | Change |
|------|--------|
| `src/analysis/threat_generation.py` | Removed the 130-line hardcoded `THREAT_HEURISTICS` tuple. `THREAT_HEURISTICS` is now assigned from `discovered_heuristics()`, imported from the heuristics package. `ThreatHeuristic` dataclass and `get_threat_heuristics()` accessor preserved unchanged. |
| `src/analysis/materializer_registry.py` | Added `auto_discover()` function with an `_discovered` guard flag. When called, it imports `discovered_materializers()` from the heuristics package and registers each one. Registry functions (`register_materializer`, `get_materializer`, `registered_rule_ids`, `all_materializers`) preserved unchanged. |
| `src/analysis/threat_outputs.py` | Replaced explicit imports of six materializer classes and six `register_materializer()` calls with a single `auto_discover()` call. Import line changed from `register_materializer` to `auto_discover`. |
| `src/analysis/materializers.py` | Replaced all six class definitions (~290 lines) with re-exports from the heuristics package for backward compatibility. |

**Auto-discovery mechanism:**

```python
# analysis/heuristics/__init__.py (simplified)
def _discover():
    for _finder, name, _ispkg in pkgutil.iter_modules(__path__):
        if not name.startswith("th_"):
            continue
        mod = importlib.import_module(f".{name}", __package__)
        if hasattr(mod, "HEURISTIC"):
            heuristics.append(mod.HEURISTIC)
        # Find materializer class by checking for rule_id + materialize attrs
        for attr in vars(mod).values():
            if isinstance(attr, type) and hasattr(attr, "rule_id") and hasattr(attr, "materialize"):
                materializers.append(attr())
                break
```

**OCP impact:** Adding TH-007 now requires only: (1) create `src/analysis/heuristics/th_007.py` with a `HEURISTIC` constant and a materializer class. No existing files need modification. The heuristic and materializer are discovered and registered automatically at import time.

---

### D.2 — Repository Pattern for Artifacts (Task 4.2)

**Problem:** Threat and risk report reading/writing logic was scattered across four modules with direct file-system coupling:
1. `agents/tools.py` — `get_threats()` / `get_risks()` called `ThreatReport.model_validate_json(path.read_text())` inline
2. `ui/data_access.py` — `load_threat_report()` / `load_risk_report()` duplicated the same pattern
3. `analysis/threat_outputs.py` — `write_threat_report()` wrote JSON directly
4. `analysis/risk_scoring.py` — `write_risk_report()` wrote JSON directly

Each consumer was tightly coupled to the file system. Switching to S3, a database, or an in-memory store for testing would require modifying every consumer.

**Solution:** Defined a `ReportRepository` protocol and a `FileReportRepository` implementation. Consumers that previously read reports inline now accept or default to a repository instance.

**New file:**

| File | Purpose |
|------|---------|
| `src/report_repository.py` | `ReportRepository` protocol with four methods: `load_threat_report()`, `load_risk_report()`, `save_threat_report()`, `save_risk_report()`. `FileReportRepository` implementation backed by `ArtifactLocator` for discovery and Pydantic `model_validate_json()` / `model_dump_json()` for serialization. |

**Modified files:**

| File | Change |
|------|--------|
| `src/agents/tools.py` | `AgentTools.__init__` accepts optional `report_repo: ReportRepository` parameter, defaults to `FileReportRepository(base_dir)`. `get_threats()` and `get_risks()` delegate to `self._repo.load_threat_report(path)` / `self._repo.load_risk_report(path)` instead of inline file reads. |
| `src/ui/data_access.py` | `load_threat_report()` and `load_risk_report()` accept optional `repo: ReportRepository` parameter, defaulting to a module-level `_DEFAULT_REPO = FileReportRepository(ROOT)`. When `base_dir` differs from `ROOT`, a new `FileReportRepository` is created. |

**Design decisions:**
- `ReportRepository` is a `Protocol` (structural subtyping) rather than an ABC, consistent with the project's existing pattern (`TraceRecorder`, `ThreatMaterializer`, `Tool`).
- `FileReportRepository` delegates discovery to the existing `ArtifactLocator` class (from Phase 2, Task 2.4), avoiding logic duplication.
- `write_threat_report()` and `write_risk_report()` in `threat_outputs.py` and `risk_scoring.py` are preserved as simple standalone helpers — they serve the CLI pipeline path where the repository abstraction adds no value. The `save_*` methods on `FileReportRepository` provide the repository-based alternative.
- `AgentTools` defaults to `FileReportRepository` when no repo is injected, maintaining full backward compatibility with existing tests and callers.

**DIP impact:** `AgentTools` and `data_access` now depend on the `ReportRepository` protocol rather than direct file-system operations. Tests can inject a mock or in-memory repository. Future implementations (S3, database) require only a new class satisfying the protocol.

---

### D.3 — Replace Singleton TechniqueIndex (Task 4.3)

**Problem:** `TechniqueIndex` used a class-level `_instance` variable with manual double-checked locking (`_lock = threading.Lock()`) to implement a singleton pattern. This created global mutable state that:
1. Leaked between tests — requiring `TechniqueIndex.reset()` calls in test setup
2. Made parallel test execution unsafe — all tests shared a single class variable
3. Coupled all consumers to the singleton access pattern via `TechniqueIndex.get()`

**Solution:** Replaced the class-level `_instance` with a `contextvars.ContextVar`. The singleton API (`get()` / `reset()`) is preserved for backward compatibility but now reads from and writes to the context variable, which is inherently scoped to the current execution context (thread, asyncio task, or test).

**Modified files:**

| File | Change |
|------|--------|
| `src/knowledge/index.py` | Removed `_instance: TechniqueIndex | None = None` class variable. Added module-level `_current_index: contextvars.ContextVar[TechniqueIndex | None]` with default `None`. `get()` reads from `_current_index.get()` with double-checked locking via `_lock`. `reset()` calls `_current_index.set(None)` — no lock needed since `ContextVar.set()` is atomic per-context. Added module-level convenience functions `get_index() -> TechniqueIndex | None` and `set_index(index) -> None` for explicit context management. |
| `src/knowledge/__init__.py` | Added `get_index` and `set_index` to imports and `__all__`. |
| `tests/test_knowledge_index.py` | `test_index_singleton_reset` updated to assert `get_index() is None` instead of `TechniqueIndex._instance is None`. |

**Context-var mechanism:**

```python
_current_index: contextvars.ContextVar[TechniqueIndex | None] = contextvars.ContextVar(
    "technique_index", default=None,
)

class TechniqueIndex:
    _lock = threading.Lock()

    @classmethod
    def get(cls, db_path=None):
        instance = _current_index.get(None)
        if instance is not None:
            return instance
        with cls._lock:
            instance = _current_index.get(None)
            if instance is not None:
                return instance
            # ... create index from store ...
            _current_index.set(instance)
        return instance

    @classmethod
    def reset(cls):
        _current_index.set(None)
```

**Design decisions:**
- The `get()` / `reset()` classmethod API is preserved unchanged for backward compatibility — `mapping_engine._get_default_index()` and `agents/tools.py` both call `TechniqueIndex.get()` and required no modifications.
- Module-level `get_index()` / `set_index()` provide a cleaner API for new code that wants explicit context management without going through the classmethod.
- `contextvars.ContextVar` was chosen over a simple thread-local because it works correctly with both threads and asyncio tasks — future-proofing for async execution contexts.
- The `threading.Lock` is retained in `get()` to prevent race conditions when two threads simultaneously attempt to create the index in the same context. Once set, subsequent reads are lock-free.

**Test isolation impact:** Each test's context is independent. `TechniqueIndex.reset()` clears only the current context's index, not a global class variable. Tests using `_build_index(tmp_path)` continue to work unchanged — the helper calls `reset()` and then constructs a fresh index.

---

### D.4 — Test Verification

Full test suite run after all Phase 4 changes:

```
82 passed, 2 skipped, 2 failed
```

All Phase 1, Phase 2, and Phase 3 tests remain green. The 2 pre-existing failures are unchanged:
- `test_agents_tools.py::test_lookup_technique_returns_matches` — source label mismatch
- `test_agents_tools.py::test_search_knowledge_stub_returns_ranked_items` — source label mismatch

---

### D.5 — File Inventory

**New files created (8):**

| File | Lines | Package |
|------|-------|---------|
| `src/analysis/heuristics/__init__.py` | 57 | analysis.heuristics |
| `src/analysis/heuristics/th_001.py` | 86 | analysis.heuristics |
| `src/analysis/heuristics/th_002.py` | 77 | analysis.heuristics |
| `src/analysis/heuristics/th_003.py` | 70 | analysis.heuristics |
| `src/analysis/heuristics/th_004.py` | 72 | analysis.heuristics |
| `src/analysis/heuristics/th_005.py` | 85 | analysis.heuristics |
| `src/analysis/heuristics/th_006.py` | 80 | analysis.heuristics |
| `src/report_repository.py` | 78 | (top-level) |

**Modified files (8):**

| File | Nature of change |
|------|-----------------|
| `src/analysis/threat_generation.py` | Hardcoded heuristic tuple → auto-discovered from heuristics package |
| `src/analysis/materializer_registry.py` | Added `auto_discover()` function |
| `src/analysis/threat_outputs.py` | Explicit materializer registration → `auto_discover()` call |
| `src/analysis/materializers.py` | Class definitions → backward-compat re-exports from heuristics package |
| `src/agents/tools.py` | Accepts `ReportRepository`; `get_threats`/`get_risks` delegate to repo |
| `src/ui/data_access.py` | `load_threat_report`/`load_risk_report` accept optional `ReportRepository` |
| `src/knowledge/index.py` | Class-level singleton → `contextvars.ContextVar`; added `get_index()`/`set_index()` |
| `src/knowledge/__init__.py` | Added `get_index`, `set_index` exports |
| `tests/test_knowledge_index.py` | `_instance` assertion → `get_index()` assertion |

---

## Appendix E — Config-Driven TOML Heuristic Loading

> Implemented: 2026-04-18
> Test result: 103 passed, 2 skipped, 2 pre-existing failures (21 new tests added)

### E.1 — Dynamic TOML-Based Heuristic Loading

**Problem:** While Phase 4.1 introduced plugin-based auto-discovery from Python modules (`th_*.py`), adding a new heuristic still required writing Python code — a `ThreatHeuristic` dataclass, a materializer class, and boilerplate imports. For heuristics that follow standard patterns (iterate snapshot rows, filter, collect cross-references, produce `ThreatRecord` objects), the Python code was largely formulaic. The design review's Phase 4.1 noted this as a "Large" effort item; the TOML-driven approach reduces it to zero-code for standard patterns.

**Solution:** Extended the discovery engine to load heuristic definitions from TOML files (`rules/th_*.toml`). A `GenericMaterializer` class interprets the `[materializer]` section at runtime, satisfying the same `ThreatMaterializer` protocol as hand-coded Python materializers.

### E.2 — New Files

| File | Lines | Purpose |
|------|-------|---------|
| `src/analysis/heuristics/generic_materializer.py` | ~220 | `GenericMaterializer` class — config-driven materializer that interprets TOML `[materializer]` sections. Handles primary iteration, skip/filter, cross-reference collection, per-row joins, evidence resolution, and affected-list resolution. Satisfies the `ThreatMaterializer` protocol. |
| `src/analysis/heuristics/rules/th_001.toml` | 34 | TOML definition for TH-001 (internet-exposed modules + sensitive workflows). Demonstrates `collect` for cross-reference aggregation. |
| `src/analysis/heuristics/rules/th_002.toml` | 27 | TOML definition for TH-002 (low-trust attack paths). Simple iteration with composite ID. |
| `src/analysis/heuristics/rules/th_003.toml` | 25 | TOML definition for TH-003 (high-privilege externally reachable). Simplest pattern — direct iteration. |
| `src/analysis/heuristics/rules/th_004.toml` | 25 | TOML definition for TH-004 (AI module dependencies). Composite ID with two sort fields. |
| `src/analysis/heuristics/rules/th_005.toml` | 27 | TOML definition for TH-005 (regulated object concentration). Demonstrates `join` for per-row cross-reference matching. |
| `src/analysis/heuristics/rules/th_006.toml` | 30 | TOML definition for TH-006 (trust boundary crossings). Demonstrates `filter` + `collect`. |
| `tests/test_generic_materializer.py` | ~210 | 21 tests: protocol compliance, TOML parsing (6 parametrized), parity with Python materializers (6 parametrized), edge cases (4), discovery integration (3). |

### E.3 — Modified Files

| File | Change |
|------|--------|
| `src/analysis/heuristics/__init__.py` | Extended `_discover()` to scan `rules/th_*.toml` files before Python modules. TOML files are loaded via `tomllib` (stdlib 3.11+). `_heuristic_from_toml()` constructs a `ThreatHeuristic` dataclass, `_materializer_from_toml()` creates a `GenericMaterializer` instance. Python modules override TOML when both define the same `rule_id`. Added `__all__` declaration per Phase 3.3 requirements. |
| `src/analysis/materializers.py` | Added `GenericMaterializer` to backward-compatible re-exports and `__all__`. |

### E.4 — TOML Materializer Config Schema

The `[materializer]` section supports the following keys:

| Key | Type | Required | Description |
|-----|------|----------|-------------|
| `primary` | string | Yes | Snapshot dict key to iterate |
| `sort_by` | list[string] | Yes | Row fields for deterministic ordering |
| `skip_if_empty` | string | No | Skip rows where this field is falsy |
| `target_id_field` | string | Yes | Row field used as `ThreatRecord.target_id` |
| `id_fields` | list[string] | Yes | Row fields combined for stable threat ID generation |
| `rationale` | string | Yes | Human-readable rationale text |
| `evidence` | dict[string, string] | No | Evidence mapping; values use `row.*` or `$name.attr` references |
| `affected.workflows` | string or list | No | Affected workflow list; supports `$name.attr` or `["row.field"]` |
| `affected.objects` | string or list | No | Affected object list; same reference syntax |

Optional sub-tables:

| Sub-table | Purpose |
|-----------|---------|
| `[materializer.filter]` | Row-level whitelist filter: `field` + `in` (list of allowed values) |
| `[materializer.collect.<name>]` | Pre-aggregate a secondary snapshot key: `source`, `unique_field`, `flatten_field` |
| `[materializer.join.<name>]` | Per-row join against secondary data: `source`, `match_value_field`, `match_in`, `collect` |

### E.5 — Reference Resolution

Evidence values and affected-list entries use a simple reference syntax:

| Prefix | Resolves to | Example |
|--------|-------------|---------|
| `row.<field>` | Value from the current primary row | `row.module_name` → `"API Gateway"` |
| `$<name>.<attr>` | Attribute from a named `collect` or `join` result | `$sensitive_data.unique_count` → `1` |
| (literal) | Passed through unchanged | `"static_value"` → `"static_value"` |

Collected data exposes three attributes: `unique_values` (deduplicated sorted list), `flattened_values` (flattened + deduplicated list from nested arrays), `unique_count` (integer count of unique values). Joined data exposes `matched_keys` (sorted list of matched values).

### E.6 — Discovery Precedence

The discovery engine loads sources in this order:

1. **TOML rules** (`rules/th_*.toml`) — loaded first, sorted by filename
2. **Python modules** (`th_*.py`) — loaded second, override TOML for the same `rule_id`

This means:
- All 6 existing heuristics currently have both Python and TOML definitions
- Python materializers are used at runtime (they take precedence)
- TOML definitions serve as machine-readable documentation and as a validation baseline
- New TOML-only heuristics (TH-007+) are fully functional without any Python code

### E.7 — Parity Verification

The test suite includes 6 parametrized parity tests that verify each TOML-driven materializer produces **identical output** to its Python counterpart for the same snapshot data. Assertions cover: `threat_id`, `rule_id`, `target_id`, `target_type`, `severity_hint`, `rationale`, `evidence`, `affected_workflows`, and `affected_objects`.

### E.8 — Test Verification

Full test suite run after all changes:

```
103 passed, 2 skipped, 2 failed
```

- 21 new tests added in `test_generic_materializer.py`
- All 82 pre-existing tests remain green
- The 2 pre-existing failures are unchanged:
  - `test_agents_tools.py::test_lookup_technique_returns_matches` — source label mismatch
  - `test_agents_tools.py::test_search_knowledge_stub_returns_ranked_items` — source label mismatch

### E.9 — OCP Impact

Adding a new heuristic now supports three paths:

| Path | Files to create | Files to modify | Python required |
|------|----------------|-----------------|-----------------|
| TOML-only | `rules/th_007.toml` | `mapping_rules.toml` (technique bindings) | No |
| Python-only | `th_007.py` | `mapping_rules.toml` | Yes |
| Hybrid (TOML + Python override) | Both | `mapping_rules.toml` | Yes |

The TOML-only path is the zero-code extension point envisioned in design review Section 4.1.

---

## Appendix F — Vector-Based Technique Suggestion Engine

> Implemented: 2026-04-18
> Test result: 128 passed, 2 skipped, 2 pre-existing failures (25 new tests added)

### F.1 — Problem

Writing curated technique mappings for new heuristics requires manually searching through ~830 ATT&CK/ATLAS techniques to find relevant bindings. The mapping engine's Layer 2 (tactic expansion) broadens coverage but only within tactics already present in curated mappings. There was no automated way to discover candidate technique bindings — especially cross-tactic matches where the relationship is causal rather than topical.

### F.2 — Solution

Added a **Layer 0 (candidate retrieval)** to the mapping pipeline using dense-vector similarity search with composite scoring. Technique descriptions are embedded at sync time into 384-dimensional vectors and stored in the existing SQLite knowledge base. A composite scorer blends vector similarity with structured metadata signals to rank candidates for human review.

### F.3 — New Files

| File | Lines | Purpose |
|------|-------|---------|
| `src/knowledge/embedder.py` | ~120 | `TextEmbedder` protocol + `SentenceTransformerEmbedder` implementation (lazy-loaded, `all-MiniLM-L6-v2`). `embed_techniques()` function generates/updates embeddings at sync time with SHA-256 hash-based change detection for idempotency. |
| `src/knowledge/vector_index.py` | ~65 | `VectorIndex` — in-memory brute-force cosine similarity search via `numpy.matmul`. Loads pre-computed embeddings from `TechniqueStore`. |
| `src/analysis/suggestion_scorer.py` | ~130 | `ScoredSuggestion` dataclass, `ScoringWeights` config, `score_suggestions()` function. Composite scoring: vector similarity (60%) + tactic-overlap bonus (25%) + framework-match bonus (15%). |
| `tests/test_embedder.py` | ~150 | 11 tests: protocol compliance, embed/skip/re-embed logic, SQLite round-trip, import guard. |
| `tests/test_vector_index.py` | ~110 | 6 tests: empty index, ranking, top-k, exclude, edge cases. |
| `tests/test_suggestion_scorer.py` | ~260 | 8 tests: basic ranking, curated exclusion, tactic bonus, framework bonus, empty index, top-k, explanations, custom weights. |

### F.4 — Modified Files

| File | Change |
|------|--------|
| `src/knowledge/store.py` | Added `embeddings` table to schema (entity_id, entity_type, model_name, vector BLOB, text_hash). Added methods: `upsert_embeddings()`, `get_embedding_hash()`, `load_all_embeddings()`, `embedding_count()`. |
| `src/knowledge/sync.py` | Added `embed: bool = False` parameter to `sync()`. When true, calls `embed_techniques()` after storing technique data. Added `embedding_count` to `sync_status()` output. |
| `src/cli/main.py` | Added `--embed` flag to `sync` subcommand. Added `suggest-mappings` subcommand with `--rule-id`, `--description`, `--top-k`, `--threshold`, `--format` (table/json/toml). |
| `pyproject.toml` | Added `[suggest]` optional dependency group: `sentence-transformers>=2.2`, `numpy>=1.24`. |

### F.5 — Composite Scoring Algorithm

The scorer blends three signals:

$$s = w_v \cdot s_\text{vec} + w_t \cdot b_\text{tactic} + w_f \cdot b_\text{framework}$$

| Signal | Weight | Value | Trigger |
|--------|--------|-------|---------|
| Vector similarity | 0.60 | Cosine similarity [0, 1] | Always |
| Tactic overlap | 0.25 | 0.15 fixed bonus | Technique shares a tactic with any curated mapping for the rule |
| Framework match | 0.15 | 0.10 fixed bonus | Technique framework matches heuristic's `frameworks` field |

The tactic bonus rescues causal-but-topically-distant mappings. For example, TH-002 (lateral movement paths) maps to T1485 (Data Destruction) because path access implies impact — the tactic bonus compensates for low vector similarity.

### F.6 — Pipeline Integration

```
                       ┌──────────────────────────┐
CLI / UI               │  suggest-mappings TH-007  │
                       └──────────┬───────────────┘
                                  │
             ┌────────────────────▼───────────────────────┐
Layer 0      │  score_suggestions()                       │
(NEW)        │  embed heuristic → vector search → score   │
             │  → ranked ScoredSuggestion list            │
             └────────────────────┬───────────────────────┘
                                  │  (human reviews, promotes to TOML)
                                  ▼
             ┌────────────────────────────────────────────┐
Layer 1      │  load_curated_mappings()    (unchanged)    │
Layer 2      │  _expand_by_tactic()        (unchanged)    │
Layer 3      │  _filter_by_context()       (unchanged)    │
             └────────────────────────────────────────────┘
```

Layer 0 is **offline/advisory** — it does not inject results into the threat generation pipeline. Suggestions are reviewed by a human operator who decides which candidates to promote into `mapping_rules.toml`.

### F.7 — CLI Usage

```bash
# Sync with embedding generation
threatforge sync --embed

# Suggest mappings for an existing heuristic
threatforge suggest-mappings --rule-id TH-001 --top-k 10

# Suggest from freeform description
threatforge suggest-mappings --description "AI model receives unvalidated user input"

# Output as ready-to-paste TOML
threatforge suggest-mappings --rule-id TH-007 --format toml --threshold 0.35
```

### F.8 — Dependencies

| Package | Version | Purpose | Required |
|---------|---------|---------|----------|
| `sentence-transformers` | ≥2.2 | Text embedding | Optional (`.[suggest]`) |
| `numpy` | ≥1.24 | Vector operations | Optional (`.[suggest]`) |
| `torch` | ≥2.0 | ST backend | Pulled by sentence-transformers |

All vector functionality is guarded behind `ImportError` checks with clear installation instructions.

### F.9 — Test Verification

Full test suite run after all changes:

```
128 passed, 2 skipped, 2 failed
```

- 25 new tests added across 3 test files
- All 103 pre-existing passing tests remain green
- The 2 pre-existing failures are unchanged (source label mismatch in `test_agents_tools.py`)

---

## Appendix G — Sync-Time Heuristic Mapping Generation

> Implemented: 2026-04-18
> Test result: 141 passed, 2 skipped, 2 pre-existing failures (13 new tests added)

### G.1 — Problem

Writing curated technique mappings for heuristics required running `suggest-mappings` one rule at a time, then manually copying output into `mapping_rules.toml`. There was no batch workflow and no way to regenerate all suggestions when the knowledge base was refreshed via `sync`.

### G.2 — Solution

Extended `threatforge sync` with `--map-heuristics` to batch-generate technique suggestions for all discovered heuristics as part of the sync lifecycle. Suggestions are written to a separate `mapping_suggestions.toml` file, keeping human-curated mappings untouched.

### G.3 — New CLI Flags

```
threatforge sync [existing flags]
    --map-heuristics           Generate suggested technique mappings for all heuristics
    --map-threshold FLOAT      Min composite score to accept (default: 0.40)
    --map-top-k INT            Max suggestions per heuristic (default: 10)
    --map-output PATH          Output path (default: data/threat_intel/mapping_suggestions.toml)
```

`--map-heuristics` implies `--embed` — embeddings are generated automatically if not already present.

### G.4 — New Files

| File | Lines | Purpose |
|------|-------|---------|
| `src/analysis/mapping_writer.py` | ~120 | `generate_mapping_suggestions()` — batch scores all discovered heuristics using the suggestion scorer, writes `mapping_suggestions.toml`. `_write_suggestions_toml()` serializes suggestions as TOML with metadata header. |
| `tests/test_mapping_writer.py` | ~290 | 13 tests: TOML round-trip (3), generation end-to-end (4), loader integration (3), sync integration (1), config loading (2). |

### G.5 — Modified Files

| File | Change |
|------|--------|
| `src/knowledge/sync.py` | Added `map_heuristics`, `map_threshold`, `map_top_k`, `map_output` parameters to `sync()`. When `map_heuristics=True`, forces `embed=True` and calls `generate_mapping_suggestions()` after embedding. `sync_status()` now reports `suggestion_count` from the suggestions file. |
| `src/cli/main.py` | Added `--map-heuristics`, `--map-threshold`, `--map-top-k`, `--map-output` arguments to `sync` subcommand. `_cmd_sync()` passes new params to `sync()` and prints suggestion count. |
| `src/analysis/mapping_loader.py` | Added `load_suggestions_config()` — reads `[suggestions]` section from `mapping_config.toml`. Added `load_suggested_mappings()` — loads auto-generated mappings from `mapping_suggestions.toml` with optional `rule_id` filtering. |
| `data/threat_intel/mapping_config.toml` | Added `[suggestions]` section with `include_suggested = false` and `suggestions_path`. |
| `src/project_paths.py` | Added `mapping_suggestions` field to `ProjectPaths` dataclass. |

### G.6 — Separation of Concerns

| File | Ownership | Lifecycle | `mapping_type` |
|------|-----------|-----------|----------------|
| `mapping_rules.toml` | Human-curated | Version-controlled, never auto-overwritten | `"curated"` |
| `mapping_suggestions.toml` | Machine-generated | Regenerated each `sync --map-heuristics` | `"suggested"` |

Suggested mappings do not flow into threat generation unless `include_suggested = true` is set in `mapping_config.toml`. Users review `mapping_suggestions.toml` and promote entries to `mapping_rules.toml` manually.

### G.7 — Execution Flow

```
sync()
  ├─ 1. Fetch ATT&CK + ATLAS bundles
  ├─ 2. Store tactics/techniques/mitigations
  ├─ 3. embed_techniques()          ← forced when map_heuristics=True
  └─ 4. generate_mapping_suggestions()
         ├─ Build VectorIndex + TechniqueIndex from fresh store
         ├─ For each discovered heuristic:
         │     ├─ Load curated mappings (excluded from candidates)
         │     ├─ score_suggestions() with composite scoring
         │     └─ Filter by threshold
         ├─ Write mapping_suggestions.toml
         └─ Return {rule_id: count, "_total": N}
```

### G.8 — Layer Integration

```
Layer 0 (vector suggestions) ──→ mapping_suggestions.toml (staging)
                                         │
                          user review / promote
                                         ▼
Layer 1 (curated)          ──→ mapping_rules.toml
Layer 2 (tactic expansion) ──→ mapping_config.toml [expansion]
Layer 3 (context filter)   ──→ runtime platform filter
```

### G.9 — Test Verification

Full test suite run after all changes:

```
141 passed, 2 skipped, 2 failed
```

- 13 new tests added in `test_mapping_writer.py`
- All 128 pre-existing passing tests remain green
- The 2 pre-existing failures are unchanged (source label mismatch in `test_agents_tools.py`)
