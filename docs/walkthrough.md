# Walkthrough Case Study

## Scenario
Demo domain: AI-enabled fintech payment platform (`fintech-ai-demo`).

Business context:
- Handles user authentication and payment execution.
- Uses AI-assisted fraud detection features.
- Processes confidential and regulated data.

Security context:
- Internet-exposed surfaces include client and gateway paths.
- Trust boundaries separate low-trust and protected domains.
- Multiple privileged services interact with critical workflows.

## End-to-end execution
### Step 1. Validate the canonical model
```bash
python scripts/validate_model.py --model models/examples/fintech_ai_platform.toml
```
Expected outcome:
- Validation succeeds with all cross-reference integrity checks.

### Step 2. Load the graph
```bash
set -a && source .env && set +a
python scripts/load_graph.py --model models/examples/fintech_ai_platform.toml --clear
```
Expected outcome:
- Neo4j graph is rebuilt with nodes and relationships for domains, modules, workflows, objects, datastores, and dependencies.

### Step 3. Generate threats
```bash
python scripts/generate_threats.py --model models/examples/fintech_ai_platform.toml
```
Expected outcome:
- Structured threats saved under `models/outputs/threats/`.
- Threats include technique mappings and rationale.

### Step 4. Score risks
```bash
python scripts/score_risks.py
```
Expected outcome:
- Prioritized risks saved under `models/outputs/risks/`.
- Each risk includes weighted score drivers and explanation text.

### Step 5. Ask analyst questions
```bash
streamlit run ui/app.py
```
Expected outcome:
- Analyst can ask natural-language questions from the Chat page.
- Responses include evidence references from graph, threat, and risk artifacts.

## Example analyst prompts
- "What are the highest risks and why?"
- "Show threats targeting api_gateway."
- "Which trust boundary crossings affect regulated objects?"
- "What does ATT&CK T1190 imply for this architecture?"
- "What AI-specific threats are mapped to ATLAS?"

## What makes this useful
- Model-first reasoning keeps outputs repeatable.
- Graph relationships support richer security context than flat checklists.
- Threat-to-risk conversion improves analyst prioritization.
- Query workflow enables transparent, tool-backed explanations.
