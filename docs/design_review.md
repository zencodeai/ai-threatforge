# Design Review — Architecture Analysis & Improvement Plan

> Generated: 2026-04-17
> Scope: Full codebase SOLID analysis, Python pattern review, phased improvement plan

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
