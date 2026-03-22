# Threat Forge AI

Threat Forge AI is a model-driven threat modeling platform that converts architecture context into explainable, analyst-ready security outputs.

## Problem and approach
Security teams often have architecture knowledge spread across diagrams, tickets, and tribal memory. Threat Forge AI addresses that by treating system architecture as code:

1. Capture system structure in a canonical TOML model.
2. Validate integrity with strict schema and cross-reference checks.
3. Load model relationships into Neo4j for path-aware analysis.
4. Generate deterministic ATT&CK and ATLAS-aligned threats.
5. Score and prioritize risks with explainable weighted factors.
6. Expose evidence-backed answers through an analyst query workflow and UI.

## Architecture overview
The end-to-end architecture is documented in:
- `docs/architecture.md`
- `docs/diagrams/architecture.mmd`

Pipeline summary:
`model -> graph -> threats -> risks -> query workflow -> UI + observability`

## What is implemented
Completed through Phase 6 PR A:
- canonical schema + validation (`models/schema/canonical_model.py`)
- graph loader + query helpers (`graph/`)
- threat generation + ATT&CK/ATLAS mappings (`analysis/`)
- deterministic risk scoring and outputs (`analysis/risk_scoring.py`)
- agent tools, routing workflow, and tracing (`agents/`)
- Streamlit analyst interface (`ui/app.py`)

## Quick start

### 1. Setup
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
```

### 2. Configure Neo4j
```bash
cp .env.example .env
```

Set these values in `.env`:
- `NEO4J_URI`
- `NEO4J_USERNAME`
- `NEO4J_PASSWORD`
- `NEO4J_DATABASE`

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

## Streamlit screens
- Model Overview: architecture entities and counts
- Threats: generated threats with ATT&CK/ATLAS mappings
- Risks: ranked risks with priority and driver context
- Analyst Chat: grounded natural-language responses with evidence refs

Note:
- The app supports both the custom `Screen` selector in `ui/app.py` and Streamlit's native multipage sidebar entries under `ui/pages/`.

The UI sidebar includes a `Run Rebuild Workflow` action that executes:
1. `scripts/validate_model.py`
2. `scripts/load_graph.py --clear`
3. `scripts/generate_threats.py`
4. `scripts/score_risks.py`

## Observability
Query workflow traces are written locally to:
- `models/outputs/traces/agent_runs.jsonl`

Events:
- `workflow_start`
- `tool_result`
- `workflow_end`

Optional LangSmith export:
```bash
pip install -e '.[observability]'
export LANGSMITH_TRACING=true
export LANGSMITH_API_KEY=<your_key>
export LANGSMITH_PROJECT=threat-forge-ai
```

## Portfolio docs and demo assets
- Architecture narrative: `docs/architecture.md`
- End-to-end walkthrough: `docs/walkthrough.md`
- Live demo script: `docs/demo_script.md`
- Diagram source: `docs/diagrams/architecture.mmd`
- Screenshot capture guide: `docs/screenshots/README.md`

## Test
```bash
pytest -q
```

## Project structure (key paths)
- `models/`: canonical examples, schema, generated artifacts
- `graph/`: Neo4j loader, constraints, reusable query helpers
- `analysis/`: threat and risk engines
- `agents/`: tool interfaces, workflow orchestration, tracing
- `ui/`: Streamlit MVP analyst interface
- `docs/`: architecture, walkthrough, and demo collateral

## License
Licensed under the Apache License 2.0. See `LICENSE`.
