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
threatforge validate --model examples/fintech_ai_platform.toml
```
Expected outcome:
- Validation succeeds with all cross-reference integrity checks.

### Step 2. Load the graph
```bash
set -a && source .env && set +a
threatforge load-graph --model examples/fintech_ai_platform.toml --clear
```
Expected outcome:
- Neo4j graph is rebuilt with nodes and relationships for domains, modules, workflows, objects, datastores, and dependencies.

### Step 3. Generate threats
```bash
threatforge generate-threats --model examples/fintech_ai_platform.toml
```
Expected outcome:
- Structured threats saved under `models/outputs/threats/`.
- Threats include technique mappings and rationale.

### Step 4. Score risks
```bash
threatforge score-risks
```
Expected outcome:
- Prioritized risks saved under `models/outputs/risks/`.
- Each risk includes weighted score drivers and explanation text.

### Step 4b. (Optional) Embed Neo4j text chunks and suggest mappings
```bash
threatforge sync --embed
threatforge suggest-mappings --rule-id TH-001 --top-k 10
```
Expected outcome:
- MITRE `TextChunk` embeddings are stored in Neo4j.
- Ranked technique suggestions are displayed with composite scores.
- Use `--format toml` to produce ready-to-paste `[[mappings]]` entries.

### Step 4c. (Optional) Batch-generate mapping suggestions at sync time
```bash
threatforge sync --map-heuristics --map-threshold 0.35
```
Expected outcome:
- Text chunks are refreshed automatically (implied by `--map-heuristics`).
- All discovered heuristics are scored against the technique corpus.
- Results are written to `data/threat_intel/mapping_suggestions.toml`.
- Curated `mapping_rules.toml` is never overwritten — review and promote manually.

### Step 5. Ask analyst questions
```bash
threatforge ui
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
