# Demo Script (10-12 Minutes)

## Audience
Security architects, engineering leaders, and hiring reviewers evaluating AI + security engineering depth.

## Setup checklist (before presenting)
1. Ensure `.env` is set for Neo4j.
2. Run model validation, graph load, threat generation, and risk scoring.
3. Confirm Streamlit app launches.
4. Keep these files ready:
- `examples/fintech_ai_platform.toml`
- the active threat and risk artifacts recorded by the current analysis manifest in `models/outputs/`

## Script flow
### 1. Open with the problem (1 minute)
"Threat modeling is often static and difficult to operationalize. Threat Forge AI keeps a canonical model as source of truth, converts it into graph-native analysis, and exposes deterministic security outputs through an analyst UI."

### 2. Show architecture pipeline (2 minutes)
- Open `docs/architecture.md` and summarize the flow:
  model -> graph -> threats -> risks -> agent -> UI.
- Highlight explainability and traceability.

### 3. Show the model (2 minutes)
- Navigate to the Model Overview page (launch with `threatforge ui`).
- Point out domains, modules, workflows, trust boundaries.
- Explain why this structure matters for security reasoning.

### 4. Show generated threats (2 minutes)
- Switch to Threats page.
- Highlight one ATT&CK-mapped and one ATLAS-mapped item.
- Call out rationale and affected targets.

### 5. Show prioritized risks (2 minutes)
- Switch to Risks page.
- Explain score, priority, and top drivers.
- Emphasize deterministic scoring and consistent ranking.

### 6. Show analyst chat (2-3 minutes)
- Ask one risk question and one technique question.
- Show evidence references and tool call payloads.
- Mention observability traces (local JSONL / optional LangSmith).
- Note that chat quality is guarded by versioned golden prompt fixtures rather than ad hoc demos.

## Closing points
- This MVP demonstrates practical AI-assisted security architecture analysis.
- Core outputs are deterministic and auditable.
- The design is extensible to mitigation planning and richer ingestion.

## Backup prompts
- "Show dependency-path risk from low-trust domains."
- "Which modules are internet-exposed and privileged?"
- "Summarize AI-relevant attack surfaces."
