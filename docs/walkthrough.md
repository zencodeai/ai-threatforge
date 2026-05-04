# Walkthrough

This walkthrough uses the example model:

- `examples/fintech_ai_platform.toml`

## Goal

Run the full pipeline and inspect the results in the UI.

## 1. Set the active model

```bash
threatforge session --model examples/fintech_ai_platform.toml
```

This stores the active model in the shared session used by both CLI and UI.

## 2. Validate the model

```bash
threatforge validate
```

Expected result:
- the model passes schema and reference validation

## 3. Load the graph

```bash
set -a && source .env && set +a
threatforge load-graph --clear
```

Expected result:
- the architecture model is loaded into Neo4j

## 4. Generate threats

```bash
threatforge generate-threats
```

Optional:

```bash
threatforge generate-threats --enrich
```

Expected result:
- a threat report is written under `models/outputs/threats/`
- the active manifest and session are updated

## 5. Score risks

```bash
threatforge score-risks
```

Expected result:
- a risk report is written under `models/outputs/risks/`
- the current manifest now points to both threat and risk artifacts

## 6. Open the UI

```bash
threatforge ui
```

Use the screens as follows:

- `Model Overview`
  Inspect modules, domains, workflows, and counts.
- `Threats`
  Review generated threats and mappings.
- `Risks`
  Review prioritized risks and score drivers.
- `Mappings`
  Review curated and suggested technique mappings.
- `Chat`
  Ask grounded analyst questions about the active run.

## Optional Knowledge Sync

If you want ATT&CK / ATLAS sync and graph-backed mapping support:

```bash
threatforge sync
threatforge sync --neo4j
threatforge sync --embed
threatforge sync --map-heuristics
```

Use this to:
- populate the local knowledge catalog
- load the knowledge graph into Neo4j
- create text chunks and embeddings
- generate suggested technique mappings

## Example Questions

- `What are the highest risks?`
- `Show threats for module api_gateway`
- `Which trust boundary crossings exist?`
- `What dependencies affect payment_service?`
- `What ATT&CK technique is T1190?`

## What To Look For

- the same active session is visible from both CLI and UI
- threat and risk artifacts are tied together through a manifest
- graph, threat, and risk answers are evidence-backed
- repeated runs stay deterministic for the same model and configuration
