# Threat Forge AI

**Model-driven threat modeling that converts architecture context into explainable, analyst-ready security outputs.**

<p align="center">
  <img src="docs/diagrams/pipeline_hero.svg" alt="Analysis pipeline: Model → Validate → Graph → Threats → Risks → Analyst UI" width="880" />
</p>

---

## The problem

Security teams often have architecture knowledge spread across diagrams, tickets, and tribal memory. Threat models are created once, rarely updated, and disconnected from the actual system structure.

## The approach

Threat Forge AI treats **architecture as code**:

1. **Define** — capture system structure in a canonical TOML model with domains, modules, workflows, trust boundaries, and data classifications.
2. **Validate** — enforce schema integrity and cross-reference checks with Pydantic contracts.
3. **Graph** — load model relationships into Neo4j for attack-path and dependency traversal.
4. **Threat** — generate deterministic ATT&CK and ATLAS-aligned threats using heuristic rules against graph patterns.
5. **Risk** — score and prioritize risks with a transparent weighted formula (six factors, four priority bands).
6. **Interact** — expose evidence-backed answers through a query workflow and Streamlit analyst UI.

Every output is **deterministic** — the same model always produces the same threats, scores, and rankings.

---

## Architecture

<p align="center">
  <img src="docs/diagrams/pipeline.svg" alt="Full architecture pipeline" width="960" />
</p>

The pipeline flows through seven layers, each with a single responsibility and well-defined I/O contract. The full architecture narrative is in [docs/architecture.md](docs/architecture.md).

### Query workflow

<p align="center">
  <img src="docs/diagrams/query_workflow.svg" alt="Query workflow routing diagram" width="720" />
</p>

Analyst questions are routed to tools via deterministic keyword matching, executed against the analysis artifacts, and composed into answers with evidence references and stated limitations.

---

## Project structure

<p align="center">
  <img src="docs/diagrams/project_structure.svg" alt="Project layout" width="720" />
</p>

| Directory | Purpose |
|---|---|
| `models/` | Canonical TOML examples, Pydantic schema contracts, generated artifacts |
| `graph/` | Neo4j client, graph loader, query helpers, Cypher constraints/indexes |
| `analysis/` | Threat generation engine, ATT&CK/ATLAS mapping, risk scoring |
| `agents/` | Tool interfaces, deterministic query workflow, observability tracing |
| `ui/` | Streamlit analyst interface (model overview, threats, risks, chat) |
| `scripts/` | CLI entry points for each pipeline stage |
| `tests/` | 49 tests across 13 modules |
| `docs/` | Architecture narrative, walkthrough, demo script, diagrams |

---

## Quick start

### 1. Install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
```

### 2. Configure Neo4j

```bash
cp .env.example .env
# Set NEO4J_URI, NEO4J_USERNAME, NEO4J_PASSWORD, NEO4J_DATABASE
```

### 3. Run the analysis pipeline

```bash
python scripts/validate_model.py --model models/examples/fintech_ai_platform.toml
set -a && source .env && set +a
python scripts/load_graph.py --model models/examples/fintech_ai_platform.toml --clear
python scripts/generate_threats.py --model models/examples/fintech_ai_platform.toml
python scripts/score_risks.py
```

### 4. Launch the analyst UI

```bash
pip install -e '.[ui]'
streamlit run ui/app.py
```

---

## Analyst screens

| Screen | Description |
|---|---|
| **Model Overview** | Architecture entities, domain counts, trust boundary summary |
| **Threats** | Generated threats with ATT&CK/ATLAS technique mappings and rationale |
| **Risks** | Priority-ranked risks with weighted score drivers and explanations |
| **Analyst Chat** | Natural-language Q&A grounded in graph, threat, and risk artifacts |

The UI sidebar includes a **Run Rebuild Workflow** action that re-executes the full pipeline (validate → load → threats → risks) in one click.

---

## Observability

Workflow traces are written locally to `models/outputs/traces/agent_runs.jsonl` with events: `workflow_start`, `tool_result`, `workflow_end`.

Optional LangSmith integration:

```bash
pip install -e '.[observability]'
export LANGSMITH_TRACING=true
export LANGSMITH_API_KEY=<your_key>
export LANGSMITH_PROJECT=threat-forge-ai
```

---

## Testing

```bash
pytest -q
```

49 tests across schema validation, graph operations, threat generation, technique mapping, risk scoring, agent workflow, observability, and UI layers.

---

## Documentation

| Document | Description |
|---|---|
| [Architecture](docs/architecture.md) | Component breakdown, trade-offs, and extension seams |
| [Walkthrough](docs/walkthrough.md) | End-to-end fintech demo case study with example prompts |
| [Demo Script](docs/demo_script.md) | Timed 10–12 minute presentation talk-track |
| [Domain Model](docs/domain_model.md) | Canonical TOML model definition and cross-reference rules |
| [Graph Schema](docs/graph_schema.md) | Neo4j node labels, relationships, constraints, and indexes |
| [Threat Methodology](docs/threat_methodology.md) | Heuristic rule catalog with ATT&CK/ATLAS alignment |
| [Risk Methodology](docs/risk_methodology.md) | Scoring formula, factor weights, and priority bands |
| [Diagrams](docs/diagrams/) | SVG pipeline, workflow, risk scoring, and project layout visuals |

---

## Tech stack

| Layer | Technology |
|---|---|
| Language | Python 3.11+ |
| Schema validation | Pydantic ≥ 2.8 |
| Graph database | Neo4j ≥ 5.20 |
| Threat mapping | MITRE ATT&CK + ATLAS |
| UI | Streamlit ≥ 1.35 |
| Observability | JSONL + LangSmith (optional) |
| Testing | pytest ≥ 8.0 |

---

## License

Licensed under the Apache License 2.0. See [LICENSE](LICENSE).
