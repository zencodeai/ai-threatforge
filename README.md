# Threat Forge AI

Threat Forge AI is a model-driven threat modeling platform.

## Current scope
- Phase 1: canonical TOML schema, validation, and example model
- Phase 2: Neo4j graph schema, idempotent graph loader, and graph loader tests
- Issue #6: reusable graph query library and analyst sample query pack
- Issue #7: deterministic threat heuristic catalog and methodology
- Issue #8: ATT&CK/ATLAS technique mapping for all threat rules
- Issue #9: structured threat output generation and artifact writing
- Phase 4 PR A/B: risk methodology, schema, and deterministic scoring engine
- Phase 4 PR C: risk scoring CLI and risk artifact generation

## Included
- Canonical TOML schema via Pydantic models
- Validation CLI script
- Realistic example model for fintech AI payment platform
- Graph schema documentation, constraints, and indexes
- Neo4j loader with idempotent `MERGE` behavior
- Reusable graph query service for analyst-facing lookups
- Sample Cypher query pack (10 queries)
- Threat heuristic catalog for Phase 3 rule definitions
- Rule-to-technique mapping catalog (ATT&CK + ATLAS)
- Structured threat report generation and JSON output artifacts
- Deterministic risk scoring with explainable driver contributions
- Unit and integration tests for schema and graph loading

## Threat heuristics
Phase 3 heuristic definitions are implemented in `analysis/threat_generation.py`
and documented in `docs/threat_methodology.md`.

Current catalog includes six deterministic rules covering:
- internet-exposed sensitive-data handling
- low-trust to high-value attack paths
- high-privilege externally reachable modules
- AI-relevant dependency exposure
- regulated data concentration in critical workflows
- trust-boundary privileged dependency crossings

## Technique mapping
Rule-to-technique mappings are implemented in `analysis/technique_mapping.py`.
This layer binds each heuristic rule (`TH-001` to `TH-006`) to ATT&CK/ATLAS
technique IDs, names, tactics, and rationale strings.

## Threat outputs
Structured threat generation is implemented in `analysis/threat_outputs.py` and
can be executed with:

```bash
set -a && source .env && set +a
python scripts/generate_threats.py --model models/examples/fintech_ai_platform.toml
```

By default this writes JSON to:
- `models/outputs/threats/<model_id>_threats.json`

## Risk scoring
Risk scoring is implemented in `analysis/risk_scoring.py` and can be executed with:

```bash
python scripts/score_risks.py
```

Optional flags:
- `--threats <path>`: explicit threat report JSON
- `--output <path>`: explicit risk report destination

By default this writes JSON to:
- `models/outputs/risks/<model_id>_risks.json`

## Prerequisites
- Python 3.11+
- Neo4j instance (for graph loading and integration tests)

## Neo4j configuration
Copy `.env.example` to `.env` and set credentials:

```bash
cp .env.example .env
```

Environment variables:
- `NEO4J_URI`
- `NEO4J_USERNAME`
- `NEO4J_PASSWORD`
- `NEO4J_DATABASE`

## Quick start
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .[dev]

# Validate canonical TOML model
python scripts/validate_model.py --model models/examples/fintech_ai_platform.toml

# Load model into Neo4j (uses .env values)
set -a && source .env && set +a
python scripts/load_graph.py --model models/examples/fintech_ai_platform.toml --clear

# Optional: inspect bundled sample Cypher queries
sed -n '1,220p' graph/cypher/sample_queries.cypher

# Run tests
pytest
```

## Test modes
- Unit/default: `pytest -q`
- Integration (requires Neo4j env vars): `set -a && source .env && set +a && pytest -q`

Integration tests are marked with `@pytest.mark.integration` in `tests/test_graph_loader.py`.

## Query pack
The repository includes a query pack for common analyst questions in
`graph/cypher/sample_queries.cypher` (10 queries), plus a Python query interface
in `graph/graph_queries.py`.

Included query themes:
- internet-exposed modules
- sensitive and regulated data flows
- trust-boundary crossings
- high-privilege externally reachable modules
- AI-relevant dependencies
- low-trust attack path candidates

## Key files
- `models/schema/canonical_model.py`: canonical schema and cross-reference validation
- `models/examples/fintech_ai_platform.toml`: demo system model
- `graph/graph_loader.py`: TOML-to-Neo4j loader
- `graph/neo4j_client.py`: Neo4j connection client
- `graph/graph_queries.py`: reusable graph query interface
- `graph/cypher/constraints.cypher`: graph constraints
- `graph/cypher/indexes.cypher`: graph indexes
- `graph/cypher/sample_queries.cypher`: analyst query pack (10 queries)
- `analysis/threat_generation.py`: Phase 3 heuristic catalog (`TH-001` to `TH-006`)
- `analysis/technique_mapping.py`: ATT&CK/ATLAS mapping catalog and lookup helpers
- `analysis/threat_outputs.py`: deterministic threat report generation and persistence
- `analysis/risk_scoring.py`: deterministic risk scoring and report generation
- `docs/graph_schema.md`: graph design and mapping
- `docs/threat_methodology.md`: threat rule intent, pattern, and output mapping
- `docs/risk_methodology.md`: risk factors, weights, priority bands, explainability
- `scripts/validate_model.py`: model validator CLI
- `scripts/load_graph.py`: graph load CLI
- `scripts/generate_threats.py`: threat artifact generation CLI
- `scripts/score_risks.py`: risk scoring CLI
- `tests/test_graph_queries.py`: query-layer unit tests
- `tests/test_threat_generation.py`: heuristic catalog guardrail tests
- `tests/test_technique_mapping.py`: technique mapping coverage and integrity tests
- `tests/test_threat_outputs.py`: structured threat output tests
- `tests/test_risk_model.py`: risk schema tests
- `tests/test_risk_scoring.py`: deterministic scoring and risk report tests
