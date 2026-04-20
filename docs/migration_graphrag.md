# GraphRAG Migration Guide

This guide covers migrating from the SQLite-only knowledge store to the Neo4j GraphRAG architecture.

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

Run the sync command with the `--neo4j` flag. This loads MITRE ATT&CK/ATLAS data into both SQLite (unchanged) and Neo4j (new):

```bash
threatforge sync --neo4j
```

This creates:
- **Technique**, **Tactic**, **Mitigation** nodes with relationships
- **HeuristicRule** nodes with `MAPS_TO` edges from curated TOML mappings
- **Module** `IMPLEMENTS_CONTROL` edges from `control_functions`
- **TextChunk** nodes with embeddings and a native vector index

The sync is idempotent — re-running updates both stores.

## Step 3: Enable GraphRAG

There are three ways to enable GraphRAG features:

### Option A: Environment variable (recommended for deployment)

```bash
export THREATFORGE_GRAPHRAG=1
```

This enables GraphRAG for all commands that support it.

### Option B: Per-command flags

```bash
# GraphRAG-enhanced technique suggestions
threatforge suggest-mappings --rule-id TH-007 --graphrag

# Threat enrichment with suggested mitigations
threatforge generate-threats --model model.toml --enrich
```

### Option C: Force legacy mode

If `THREATFORGE_GRAPHRAG=1` is set but you need the SQLite path:

```bash
threatforge suggest-mappings --rule-id TH-007 --legacy
threatforge generate-threats --model model.toml --legacy
```

## What Changes

### Technique Suggestions (`suggest-mappings`)

| Feature | Legacy (SQLite) | GraphRAG (Neo4j) |
|---|---|---|
| Similarity search | In-memory NumPy matmul | Neo4j native vector index |
| Scoring signals | Vector + tactic + framework | Vector + tactic + framework + mitigation gap + sub-technique |
| Context | Flat technique list | Graph-traversed tactics, mitigations, sub-techniques |

### Threat Reports (`generate-threats`)

With `--enrich` or `THREATFORGE_GRAPHRAG=1`, threat records gain two new fields:

- **`suggested_mitigations`**: Mitigations for mapped techniques NOT implemented by the target module's `control_functions`
- **`related_techniques`**: Techniques linked by shared mitigations or parent/sub-technique hierarchy

Without enrichment, output is identical to the legacy path. The new fields default to empty lists, so downstream consumers are not affected.

## Deprecation Notices

The following components emit `DeprecationWarning` when used:

| Component | Replacement |
|---|---|
| `VectorIndex` | `GraphVectorSearch` |
| `TechniqueStore.upsert_embeddings()` | `ChunkingPipeline.process()` |
| `TechniqueStore.load_all_embeddings()` | `GraphVectorSearch.search()` |

These components remain functional for deployments without Neo4j. To suppress warnings:

```python
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning, module="knowledge")
```

## Rollback

To revert to the legacy path:

1. Unset the environment variable: `unset THREATFORGE_GRAPHRAG`
2. Remove `--graphrag` / `--enrich` flags from any scripts
3. The SQLite knowledge store continues to work as before

No data migration is needed in either direction — both stores are populated independently by `threatforge sync`.

## Verifying the Migration

```bash
# Check Neo4j is populated
threatforge sync --status

# Test GraphRAG suggestions
threatforge suggest-mappings --rule-id TH-007 --graphrag --format json

# Test enriched threat generation
threatforge generate-threats --model examples/fintech_ai_platform.toml --enrich

# Run the test suite
python -m pytest -v
```
