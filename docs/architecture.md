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
| **Source** | `models/examples/*.toml` |
| **Contract** | `models/schema/canonical_model.py` (Pydantic) |
| **Entities** | systems, domains, modules, workflows, objects, datastores, trust boundaries, privilege levels |
| **Responsibility** | Provide the single source of truth for architecture structure and security metadata. Cross-reference integrity is enforced at validation time. |

### 2. Graph layer

| Attribute | Detail |
|---|---|
| **Source** | `graph/graph_loader.py`, `graph/graph_queries.py` |
| **Storage** | Neo4j with constraints and indexes (`graph/cypher/`) |
| **Key queries** | neighbours, dependency paths, trust-boundary crossings, exposure checks |
| **Responsibility** | Project the canonical model into a graph database that supports attack-path and dependency traversal queries with sub-second latency. |

### 3. Threat layer

| Attribute | Detail |
|---|---|
| **Source** | `analysis/threat_generation.py`, `analysis/technique_mapping.py`, `analysis/threat_outputs.py` |
| **Output** | `models/outputs/threats/*_threats.json` |
| **Mapping** | MITRE ATT&CK (enterprise techniques) and MITRE ATLAS (AI/ML techniques) |
| **Responsibility** | Apply heuristic rules against graph patterns to generate structured, mapped threat candidates with rationale text explaining *why* each threat applies. |

### 4. Risk layer

<p align="center">
  <img src="diagrams/risk_scoring.svg" alt="Risk scoring methodology" width="780" />
</p>

| Attribute | Detail |
|---|---|
| **Source** | `analysis/risk_scoring.py` |
| **Output** | `models/outputs/risks/*_risks.json` |
| **Formula** | Weighted sum across six factors: likelihood (0.25), impact (0.20), exposure (0.15), privilege sensitivity (0.15), data criticality (0.15), exploitability (0.10) |
| **Responsibility** | Convert each threat into a deterministic risk score with priority band (critical / high / medium / low) and human-readable driver explanations. |

### 5. Agent / query layer

<p align="center">
  <img src="diagrams/query_workflow.svg" alt="Query workflow routing" width="720" />
</p>

| Attribute | Detail |
|---|---|
| **Source** | `agents/tools.py`, `agents/workflow.py`, `agents/state.py` |
| **Tools** | `list_threats`, `list_risks`, `graph_query`, `technique_lookup`, `search_knowledge` |
| **Responsibility** | Accept analyst questions, route them to the correct tool(s) via deterministic keyword matching, execute grounded lookups, and compose an `AgentAnswer` with evidence references and stated limitations. |

### 6. Observability layer

| Attribute | Detail |
|---|---|
| **Source** | `agents/observability.py` |
| **Local output** | `models/outputs/traces/agent_runs.jsonl` (structured event log) |
| **Optional** | LangSmith export via `.[observability]` extra |
| **Events** | `workflow_start`, `tool_result`, `workflow_end` |
| **Responsibility** | Record every workflow invocation for audit, debugging, and performance review. The composite recorder pattern supports simultaneous local and remote tracing. |

### 7. UI layer

| Attribute | Detail |
|---|---|
| **Source** | `ui/app.py`, `ui/pages/*` |
| **Framework** | Streamlit (`.[ui]` extra) |
| **Screens** | Model Overview · Threats · Risks · Analyst Chat |
| **Responsibility** | Provide analyst workflows for exploring model structure, reviewing generated threats and risks, and running natural-language queries against the analysis outputs. Includes a one-click rebuild action that re-runs the full pipeline. |

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
