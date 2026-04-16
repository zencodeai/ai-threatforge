# Threat Forge AI — Architecture

> Model-driven threat modeling: deterministic components produce repeatable, explainable security outputs; agent workflows provide analyst interaction on top.

---

## Pipeline overview

<p align="center">
  <img src="diagrams/pipeline.svg" alt="End-to-end analysis pipeline" width="960" />
</p>

Architecture data flows through seven layers, each with a single clear responsibility and a well-defined input/output contract. All core analysis is **deterministic** — the same model always produces the same threats and risk scores.

---

## Components

### 1. Canonical model layer

| Attribute | Detail |
|---|---|
| **Source** | `examples/*.toml` |
| **Contract** | `src/models/schema/canonical_model.py` (Pydantic) |
| **Entities** | systems, domains, modules, workflows, objects, datastores, trust boundaries, privilege levels |
| **Responsibility** | Provide the single source of truth for architecture structure and security metadata. Cross-reference integrity is enforced at validation time. |

Architecture definitions are authored in **TOML** — a format chosen for human readability and minimal syntax noise compared to YAML or JSON. Each file describes a complete system: its security domains (trust zones), modules (services and components), data objects with classification levels, workflows that tie modules and data together, and the trust boundaries and dependencies between them.

**Pydantic v2** validates every model at load time. Beyond basic type checking, a custom `model_validator` enforces cross-reference integrity: every module must reference an existing domain, every workflow must reference existing modules and objects, every dependency must connect valid source and target IDs. Duplicate IDs and dangling references are caught before any downstream analysis runs. This contract guarantees that the graph loader, threat engine, and risk engine all receive structurally sound input.

### 2. Graph layer

| Attribute | Detail |
|---|---|
| **Source** | `src/graph/neo4j_client.py`, `src/graph/graph_loader.py`, `src/graph/graph_queries.py` |
| **Storage** | Neo4j with constraints and indexes (`src/graph/cypher/`) |
| **Protocol** | Bolt (via the official `neo4j` Python driver) |
| **Key queries** | neighbours, dependency paths, trust-boundary crossings, exposure checks, attack-path traversal |
| **Responsibility** | Project the canonical model into a property graph that supports path-aware security analysis with sub-second latency. |

**Why Neo4j?** Security analysis is fundamentally a graph problem. Questions like "can a low-trust module reach a regulated datastore through a chain of dependencies?" or "which trust boundaries does this workflow cross?" require multi-hop traversal that a relational database handles poorly. Neo4j's **Cypher** query language makes these patterns concise and performant.

The graph loader creates **9 node types** (`System`, `SecurityDomain`, `PrivilegeLevel`, `Module`, `Object`, `DataStore`, `ExternalActor`, `Workflow`, `TrustBoundary`) and **16 relationship types** (including `DEPENDS_ON`, `IN_DOMAIN`, `HAS_PRIVILEGE`, `STORES`, `INVOLVES_MODULE`, `CROSSES_FROM`/`CROSSES_TO`, and system-level ownership edges). All writes use `MERGE` on ID keys, making the loader fully **idempotent** — running it twice with the same model produces identical state.

Schema enforcement is applied at the database level: **unique constraints** on every entity ID prevent duplicates, and **indexes** on `internet_exposed`, `ai_relevant`, `classification`, and `regulated` fields accelerate the filtered queries that threat heuristics depend on.

Ten **pre-built named queries** cover the most common security analysis patterns:

| Query | Purpose |
|---|---|
| `internet_exposed_modules` | Find public-facing services |
| `high_value_objects_crossing_boundaries` | Sensitive data crossing trust zones |
| `workflows_involving_sensitive_data` | Workflows handling confidential/secret/regulated objects |
| `high_privilege_externally_reachable_modules` | Privileged services exposed to external actors |
| `modules_depending_on_ai_services` | Non-AI modules with AI dependencies |
| `low_to_high_trust_attack_paths` | Dependency chains from low-trust to high-value (up to 5 hops) |
| `dependency_edges` | All module/datastore dependencies |
| `trust_boundary_crossings` | All trust boundary definitions |

Custom Cypher queries can also be executed directly through the agent tool layer.

### 3. Threat layer

| Attribute | Detail |
|---|---|
| **Source** | `src/analysis/threat_generation.py`, `src/analysis/technique_mapping.py`, `src/analysis/threat_outputs.py` |
| **Output** | `models/outputs/threats/*_threats.json` |
| **Mapping** | MITRE ATT&CK (enterprise techniques) and MITRE ATLAS (AI/ML techniques) |
| **Responsibility** | Apply heuristic rules against graph patterns to generate structured, mapped threat candidates with rationale text explaining *why* each threat applies. |

The threat engine runs **six deterministic heuristics** (TH-001 through TH-006), each defined as a `ThreatHeuristic` dataclass specifying a graph pattern, target type, severity hint, and applicable frameworks:

| Rule | Threat Pattern | Severity | Framework |
|---|---|---|---|
| TH-001 | Internet-exposed module handling sensitive workflow data | High | ATT&CK |
| TH-002 | Low-trust to high-value object dependency path | Critical | ATT&CK |
| TH-003 | High-privilege module externally reachable | High | ATT&CK |
| TH-004 | AI-relevant module dependency and model service exposure | High | ATT&CK + ATLAS |
| TH-005 | Regulated object concentration in critical workflows | High | ATT&CK |
| TH-006 | Trust boundary crossing with privileged dependency | Medium | ATT&CK |

Each heuristic is executed as a Cypher query against the Neo4j graph. Matched patterns are expanded into `ThreatRecord` objects with structured evidence (affected modules, objects, workflows, paths) and human-readable rationale.

**MITRE ATT&CK / ATLAS mapping** is handled by a dedicated mapping catalog in `technique_mapping.py`. Each `rule_id` maps to one or more `TechniqueMapping` entries containing the technique ID (e.g., `T1190`, `AML.T0016`), tactic category (e.g., Initial Access, Defense Evasion), and a rationale explaining the alignment. Coverage validation ensures every heuristic has at least one technique mapping. Example mappings:

- TH-001 → T1190 (Exploit Public-Facing Application), T1078 (Valid Accounts)
- TH-004 → AML.T0016 (Obtain Capabilities — Data Poisoning), AML.T0040 (ML Model Evasion)
- TH-005 → T1530 (Data from Cloud Storage), T1020 (Automated Exfiltration)

### 4. Risk layer

<p align="center">
  <img src="diagrams/risk_scoring.svg" alt="Risk scoring methodology" width="780" />
</p>

| Attribute | Detail |
|---|---|
| **Source** | `src/analysis/risk_scoring.py` |
| **Output** | `models/outputs/risks/*_risks.json` |
| **Formula** | Weighted sum across six factors: likelihood (0.25), impact (0.20), exposure (0.15), privilege sensitivity (0.15), data criticality (0.15), exploitability (0.10) |
| **Responsibility** | Convert each threat into a deterministic risk score with priority band (critical / high / medium / low) and human-readable driver explanations. |

Each threat record is passed through six **scoring functions** that extract normalised factors from the threat's evidence, severity, target type, and technique mappings:

- **Likelihood** — base severity score + bonuses for internet exposure, workflow involvement, and rule-specific patterns.
- **Impact** — base severity + target-type weight (workflows and systems score higher) + affected-object count scaling.
- **Exposure** — base 0.30 + internet-exposure bonus (0.30) + trust-boundary crossings + dependency hop count.
- **Privilege sensitivity** — privilege level scaled proportionally (higher privilege → higher score, capped at 0.60).
- **Data criticality** — object classification level + regulated-data presence + affected-object count.
- **Exploitability** — number of mapped ATT&CK/ATLAS techniques + tactic-specific bonuses (Initial Access +0.20, Lateral Movement +0.15, Privilege Escalation +0.10).

The final score is a weighted sum clamped to `[0.0, 1.0]`. Each `RiskRecord` includes the top three contributing factors as `RiskDriver` objects with their weighted contribution values, plus a plain-language explanation. The report is sorted by score descending, so the most critical risks surface first.

### 5. Agent / query layer

<p align="center">
  <img src="diagrams/query_workflow.svg" alt="Query workflow routing" width="720" />
</p>

| Attribute | Detail |
|---|---|
| **Source** | `src/agents/tools.py`, `src/agents/workflow.py`, `src/agents/state.py` |
| **Tools** | `query_graph`, `get_threats`, `get_risks`, `lookup_technique`, `search_knowledge` |
| **Responsibility** | Accept analyst questions, route them to the correct tool(s) via deterministic keyword matching, execute grounded lookups, and compose an `AgentAnswer` with evidence references and stated limitations. |

The query workflow is intentionally **deterministic — no LLM calls** are made during routing or answer composition. This is a deliberate design choice: the agent layer adds value through structured presentation and tool orchestration, not through generative inference.

**Routing** uses a two-stage pattern matcher:
1. **Regex match** — technique IDs like `T1190` or `AML.T0016` trigger `lookup_technique` immediately.
2. **Keyword match** — terms like "risk", "threat", "graph", "dependency", "explain" route to the corresponding tool. Multiple tools can fire for a single question.
3. **Fallback** — unmatched questions fall through to `search_knowledge`.

Each tool returns a structured `ToolResponse` (Pydantic model) with `ok`, `source`, `evidence` (list of dicts), `confidence` (0.0–1.0), and optional error metadata. The **answer composer** aggregates tool results into an `AgentAnswer` containing the summary text, `evidence_refs` (traceable back to source artifacts), and `limitations` (explicitly stating what the workflow could not answer). All tool invocations are recorded in `AgentState` as `ToolCallRecord` objects for full auditability.

The five tools cover the full analysis surface:

| Tool | Data Source | Returns |
|---|---|---|
| `query_graph` | Neo4j (live Cypher) | Graph traversal results |
| `get_threats` | `*_threats.json` artifact | Filtered threat records |
| `get_risks` | `*_risks.json` artifact | Top-N ranked risk records |
| `lookup_technique` | In-memory mapping catalog | ATT&CK/ATLAS technique details |
| `search_knowledge` | Heuristic + mapping corpus | Full-text matches across rules and mappings |

### 6. Observability layer

| Attribute | Detail |
|---|---|
| **Source** | `src/agents/observability.py` |
| **Local output** | `models/outputs/traces/agent_runs.jsonl` (structured event log) |
| **Optional** | LangSmith export via `.[observability]` extra |
| **Events** | `workflow_start`, `tool_result`, `workflow_end` |
| **Responsibility** | Record every workflow invocation for audit, debugging, and performance review. The composite recorder pattern supports simultaneous local and remote tracing. |

Observability is built on a **protocol-based recorder pattern** (`TraceRecorder` protocol) with four implementations:

- **`NullTraceRecorder`** — no-op, used in tests to avoid side effects.
- **`JsonlTraceRecorder`** — appends structured JSON events to a local file. Each event carries a UTC timestamp, unique `run_id` (format: `run-{12-hex}`), the analyst question, tool responses, and the final composed answer.
- **`LangSmithTraceRecorder`** — exports traces to **LangSmith** for cloud-based monitoring and analytics. Creates parent-child run relationships (workflow run → individual tool runs) and attaches full response payloads. Activated by setting `LANGSMITH_TRACING=true` and providing `LANGSMITH_API_KEY` and `LANGSMITH_PROJECT`.
- **`CompositeTraceRecorder`** — chains multiple recorders so local JSONL and LangSmith tracing run simultaneously.

The factory function `create_trace_recorder()` auto-detects the environment and returns the appropriate composite configuration.

### 7. UI layer

| Attribute | Detail |
|---|---|
| **Source** | `src/ui/app.py`, `src/ui/pages/*` |
| **Framework** | Streamlit (`.[ui]` extra) |
| **Screens** | Model Overview · Threats · Risks · Analyst Chat |
| **Responsibility** | Provide analyst workflows for exploring model structure, reviewing generated threats and risks, and running natural-language queries against the analysis outputs. Includes a one-click rebuild action that re-runs the full pipeline. |

The UI is built with **Streamlit** for rapid prototyping with minimal frontend code. It uses Streamlit's native multipage pattern — each screen is a standalone module under `src/ui/pages/` that can be rendered independently or routed from the main app shell.

The sidebar provides two interaction modes:
- **Model selection** — choose from bundled example models or upload a custom TOML file.
- **Rebuild workflow** — a single button that sequentially runs `validate_model.py` → `load_graph.py --clear` → `generate_threats.py` → `score_risks.py`, with per-step stdout/stderr feedback.

Data access is handled through `src/ui/data_access.py`, which loads Pydantic-validated models and JSON artifacts, builds summary views, and discovers the latest output files via glob patterns. All data flows are read-only — the UI never mutates analysis artifacts directly.

---

## Architecture trade-offs

| Decision | Rationale |
|---|---|
| **Determinism over generative inference** | Core scoring and threat generation use fixed rules so outputs are repeatable and auditable. |
| **Local-first execution** | All data and analysis run on the developer's machine — no cloud dependency for the MVP. |
| **Agent as interaction layer, not source of truth** | The query workflow adds value through presentation and routing; it does not invent new threats or scores. |
| **Explicit JSON outputs** | `threats.json` and `risks.json` are first-class artifacts that downstream tools or CI pipelines can consume. |
| **Optional observability** | Tracing is always available locally; LangSmith integration is opt-in to keep the core dependency footprint small. |

---

## Extension seams

| Extension | Description |
|---|---|
| **RAG-backed knowledge search** | Replace the stub `search_knowledge` tool with a retriever-backed connector (e.g., vector store over internal security policies). |
| **Additional ingestion channels** | Ingest SBOMs, IaC definitions, or code metadata alongside TOML models. |
| **Mitigation generation** | Map threats to control frameworks and generate recommended mitigations with coverage scores. |
| **Red-team plan export** | Produce structured red-team engagement plans from high-priority threats. |
| **Multi-project workspace** | Evolve the UI and data layer to manage and compare multiple architecture models. |

---

## Diagram sources

| Diagram | File |
|---|---|
| Full pipeline | `docs/diagrams/pipeline.svg` |
| Query workflow | `docs/diagrams/query_workflow.svg` |
| Risk scoring | `docs/diagrams/risk_scoring.svg` |
| Project layout | `docs/diagrams/project_structure.svg` |
