# ThreatGraph AI

ThreatGraph AI is a model-driven threat modeling platform.

## Current scope
- Phase 1: canonical TOML schema, validation, and example model
- Phase 2: Neo4j graph schema, idempotent graph loader, and graph loader tests

## Included
- Canonical TOML schema via Pydantic models
- Validation CLI script
- Realistic example model for fintech AI payment platform
- Graph schema documentation, constraints, and indexes
- Neo4j loader with idempotent `MERGE` behavior
- Unit and integration tests for schema and graph loading

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

# Run tests
pytest
```

## Test modes
- Unit/default: `pytest -q`
- Integration (requires Neo4j env vars): `set -a && source .env && set +a && pytest -q`

Integration tests are marked with `@pytest.mark.integration` in `tests/test_graph_loader.py`.

## Key files
- `models/schema/canonical_model.py`: canonical schema and cross-reference validation
- `models/examples/fintech_ai_platform.toml`: demo system model
- `graph/graph_loader.py`: TOML-to-Neo4j loader
- `graph/neo4j_client.py`: Neo4j connection client
- `graph/cypher/constraints.cypher`: graph constraints
- `graph/cypher/indexes.cypher`: graph indexes
- `docs/graph_schema.md`: graph design and mapping
- `scripts/validate_model.py`: model validator CLI
- `scripts/load_graph.py`: graph load CLI
