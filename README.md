# Threat Forge AI

Threat Forge AI is a model-driven threat modeling system. It turns a canonical architecture model into:

- a validated system description
- a Neo4j architecture graph
- deterministic threat findings
- prioritized risk findings
- evidence-backed analyst queries in CLI and UI

The system is deterministic by design. The same model and knowledge state produce the same threats, risks, and routed query behavior.

## What It Does

1. Author a system model in TOML.
2. Validate it with strict schema and cross-reference checks.
3. Load it into Neo4j.
4. Generate threats from graph-backed heuristics.
5. Score risks from those threats.
6. Explore the results in the CLI, UI, or analyst query workflow.

## Architecture

The current system has six main layers:

1. `src/models/`
   Canonical model schema and output schemas.
2. `src/graph/`
   Neo4j client, graph loader, and named graph queries.
3. `src/knowledge/`
   ATT&CK / ATLAS sync, local catalog, and graph-backed retrieval support.
4. `src/analysis/`
   Threat generation, technique mapping, enrichment, and risk scoring.
5. `src/agents/`
   Deterministic routing, tool execution, answer composition, and tracing.
6. `src/ui/`
   Streamlit analyst interface.

More detail is in [docs/architecture.md](docs/architecture.md).

## Quick Start

### Install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
```

### Configure Neo4j

```bash
cp .env.example .env
# Set NEO4J_URI, NEO4J_USERNAME, NEO4J_PASSWORD, NEO4J_DATABASE
set -a && source .env && set +a
```

### Optional: sync the knowledge base

```bash
threatforge sync
threatforge sync --neo4j
threatforge sync --embed
threatforge sync --map-heuristics
threatforge sync --status
```

### Run the pipeline

```bash
threatforge session --model examples/fintech_ai_platform.toml
threatforge validate
threatforge load-graph --clear
threatforge generate-threats
threatforge score-risks
threatforge session
```

### Launch the UI

```bash
pip install -e '.[ui]'
threatforge ui
```

## Shared Session Model

CLI and UI share a persisted session. The session tracks:

- active model
- active analysis manifest
- current threat artifact
- current risk artifact

That keeps repeated CLI calls and the UI aligned to the same analysis run.

## Main Outputs

- `models/outputs/threats/`
  Threat reports.
- `models/outputs/risks/`
  Risk reports.
- `models/outputs/manifests/`
  Analysis run manifests.
- `models/outputs/traces/`
  Analyst query trace events.

## Analyst Query Workflow

The query system is deterministic. It does not generate threats or scores itself. It routes questions to tools over:

- graph queries
- threat reports
- risk reports
- technique mappings
- knowledge search

Answers include evidence references and explicit limitations. Query quality is regression-tested with versioned golden prompt suites.

## Project Layout

| Path | Purpose |
|---|---|
| `examples/` | Example system models |
| `data/threat_intel/` | Mapping rules, config, suggestions, local knowledge DB |
| `models/outputs/` | Threats, risks, manifests, traces |
| `src/models/` | Schema contracts |
| `src/graph/` | Graph loading and query layer |
| `src/knowledge/` | ATT&CK / ATLAS sync and retrieval support |
| `src/analysis/` | Threat and risk engines |
| `src/agents/` | Query workflow and tracing |
| `src/ui/` | Streamlit UI |
| `src/cli/` | CLI entrypoint |
| `tests/` | Automated test suite |

## Testing

```bash
pytest -q
```

Current suite status: `361 passed, 2 skipped`.

## Core Docs

| Document | Use |
|---|---|
| [docs/architecture.md](docs/architecture.md) | Current system architecture |
| [docs/walkthrough.md](docs/walkthrough.md) | End-to-end usage flow |
| [docs/threat_methodology.md](docs/threat_methodology.md) | Threat engine behavior and heuristic structure |
| [docs/risk_methodology.md](docs/risk_methodology.md) | Risk scoring model |
| [docs/domain_model.md](docs/domain_model.md) | Canonical model format |
| [docs/graph_schema.md](docs/graph_schema.md) | Neo4j graph schema |
| [tests/fixtures/nlp_quality/README.md](tests/fixtures/nlp_quality/README.md) | Query quality fixture format |

## License

Apache 2.0. See [LICENSE](LICENSE).
