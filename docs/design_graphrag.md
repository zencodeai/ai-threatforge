# Design: Neo4j GraphRAG Integration

> Status: Implemented
> Updated: 2026-04-20

## 1. Summary

ThreatForge now uses a graph-backed suggestion and enrichment pipeline:

- MITRE ATT&CK and ATLAS metadata are synced into a local SQLite catalog for deterministic lookups and offline metadata access.
- The same corpus is projected into Neo4j as `Technique`, `Tactic`, `Mitigation`, `HeuristicRule`, and `TextChunk` nodes.
- `TextChunk.embedding` is indexed with Neo4j native vector search.
- `GraphRAGScorer` powers `threatforge suggest-mappings` and `sync --map-heuristics`.
- `ThreatEnricher` uses the graph to attach `suggested_mitigations` and `related_techniques` during `generate-threats --enrich`.

The removed runtime pieces are:

- `src/knowledge/vector_index.py`
- `src/analysis/suggestion_scorer.py`
- SQLite embedding persistence APIs from `TechniqueStore`

## 2. Runtime Architecture

```text
MITRE sync inputs
    -> SQLite TechniqueStore (catalog + sync metadata)
    -> Neo4j KnowledgeGraphLoader
         -> Technique / Tactic / Mitigation nodes
         -> HeuristicRule + MAPS_TO bridges
         -> Module IMPLEMENTS_CONTROL bridges
         -> ChunkingPipeline
              -> TextChunk nodes
              -> native vector index

suggest-mappings
    -> SentenceTransformerEmbedder
    -> GraphVectorSearch
    -> GraphRAGScorer
    -> mapping_suggestions.toml or CLI output

generate-threats --enrich
    -> Threat engine
    -> ThreatEnricher
    -> suggested_mitigations / related_techniques
```

## 3. Graph Schema Additions

The GraphRAG layer extends the architecture graph with these MITRE-side nodes:

- `Technique`
- `Tactic`
- `Mitigation`
- `HeuristicRule`
- `TextChunk`

Key relationships:

- `(:Technique)-[:IN_TACTIC]->(:Tactic)`
- `(:Technique)-[:IS_SUBTECHNIQUE_OF]->(:Technique)`
- `(:Technique)-[:MITIGATED_BY]->(:Mitigation)`
- `(:TextChunk)-[:CHUNK_OF]->(:Technique | :Mitigation)`
- `(:HeuristicRule)-[:MAPS_TO]->(:Technique)`
- `(:Module)-[:IMPLEMENTS_CONTROL]->(:Mitigation)`

The vector index is defined on `TextChunk.embedding` and queried through `GraphVectorSearch`.

## 4. Scoring Model

`GraphRAGScorer` combines:

- vector similarity: `0.45`
- tactic overlap: `0.15`
- framework match: `0.10`
- mitigation gap: `0.20`
- sub-technique bonus: `0.10`

The scorer is advisory only. Curated mappings remain the authoritative input to threat generation unless the user explicitly enables suggested mappings in `mapping_config.toml`.

## 5. Sync Lifecycle

`threatforge sync` always refreshes the local MITRE catalog.

Optional sync flags:

- `--neo4j`: load the MITRE graph into Neo4j
- `--embed`: run the chunking pipeline and write `TextChunk` embeddings
- `--map-heuristics`: imply the graph-backed chunk refresh path and generate `mapping_suggestions.toml`

Sync status now reports `text_chunk_count` instead of legacy embedding counts.

## 6. CLI and UI Behavior

- `threatforge suggest-mappings` is GraphRAG-only.
- `threatforge generate-threats --enrich` enables graph-backed mitigation and related-technique enrichment.
- The Streamlit UI exposes:
  - sync status
  - chunk/embed controls for Neo4j
  - mapping suggestion review and promotion
  - rebuild-time enrichment toggle

There is no `--legacy` or `--graphrag` transition mode for suggestions anymore.

## 7. Operational Notes

- Neo4j connectivity is required for `suggest-mappings`, `--embed`, `--map-heuristics`, and threat enrichment.
- The optional `.[suggest]` extra still provides `sentence-transformers` for chunk embedding and query embedding.
- The local SQLite catalog remains useful for fast deterministic lookups in the CLI, agent tools, and UI.

## 8. Related Docs

- [architecture.md](architecture.md)
- [migration_graphrag.md](migration_graphrag.md)
- [graph_schema.md](graph_schema.md)
