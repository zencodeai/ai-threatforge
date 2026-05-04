# GraphRAG Migration Guide

This guide reflects the final graph-backed runtime. The old SQLite embedding/vector fallback has been removed; `suggest-mappings` now always uses the Neo4j GraphRAG pipeline.

## Prerequisites

- Neo4j 5.18+ (5.20+ recommended for vector index performance)
- Python dependencies already satisfied (`neo4j>=5.20,<6.0` is in the base install)
- `sentence-transformers>=2.2` (install with `pip install -e '.[suggest]'`)

## Step 1: Configure Neo4j Connection

Set the following environment variables:

```bash
export NEO4J_URI="bolt://localhost:7687"
export NEO4J_USERNAME="neo4j"
export NEO4J_PASSWORD="your-password"
export NEO4J_DATABASE="neo4j"  # optional, defaults to "neo4j"
```

## Step 2: Populate the Knowledge Graph

Run the sync command with the `--neo4j` flag. This loads MITRE ATT&CK/ATLAS data into the local technique catalog and the Neo4j knowledge graph:

```bash
threatforge sync --neo4j
```

This creates:
- **Technique**, **Tactic**, **Mitigation** nodes with relationships
- **HeuristicRule** nodes with `MAPS_TO` edges from curated TOML mappings
- **Module** `IMPLEMENTS_CONTROL` edges from `control_functions`
- **TextChunk** nodes with embeddings and a native vector index

The sync is idempotent — re-running refreshes both stores.

## Step 3: Enable Enrichment

Technique suggestions already use GraphRAG. The remaining optional switch is threat enrichment.

### Option A: Environment variable (recommended for deployment)

```bash
export THREATFORGE_GRAPHRAG=1
```

This enables enrichment-aware commands by default.

### Option B: Per-command flags

```bash
# Threat enrichment with suggested mitigations
threatforge generate-threats --model model.toml --enrich
```

## What Changes

### Technique Suggestions (`suggest-mappings`)

| Capability | Current behavior |
|---|---|
| Similarity search | Neo4j native vector index over `TextChunk.embedding` |
| Scoring signals | Vector + tactic + framework + mitigation gap + sub-technique |
| Context | Graph traversal across tactics, mitigations, and sub-techniques |

### Threat Reports (`generate-threats`)

With `--enrich` or `THREATFORGE_GRAPHRAG=1`, threat records gain two new fields:

- **`suggested_mitigations`**: Mitigations for mapped techniques NOT implemented by the target module's `control_functions`
- **`related_techniques`**: Techniques linked by shared mitigations or parent/sub-technique hierarchy

Without enrichment, output keeps the same deterministic threat records and leaves the new fields empty.

## Verifying the Migration

```bash
# Check Neo4j is populated
threatforge sync --status

# Test graph-backed suggestions
threatforge suggest-mappings --rule-id TH-007 --format json

# Test enriched threat generation
threatforge generate-threats --model examples/fintech_ai_platform.toml --enrich

# Run the test suite
python -m pytest -v
```
