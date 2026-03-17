# ThreatGraph AI

Phase 1 foundation for a model-driven threat modeling platform.

## Included in Phase 1
- Canonical TOML schema via Pydantic models
- Validation CLI script
- Realistic example model for fintech AI payment platform
- Schema tests with valid and invalid cases

## Quick start
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
python scripts/validate_model.py --model models/examples/fintech_ai_platform.toml
pytest
```
