# Design: Neo4j GraphRAG Integration

> Status: Proposed  
> Author: ThreatForge Team  
> Date: 2026-04-20

## 1. Motivation

ThreatForge currently splits threat intelligence across two storage systems:

- **Neo4j** stores the canonical architecture model (modules, dependencies, workflows, trust boundaries) and runs 50+ Cypher pattern-detection queries to produce a snapshot that heuristic materializers consume.
- **SQLite** (`threatforge_kb.db`) stores the MITRE ATT&CK/ATLAS corpus (tactics, techniques, mitigations) with pre-computed 384-dimensional sentence-transformer embeddings. An in-memory NumPy brute-force index provides cosine similarity search for the technique suggestion engine (Layer 0).

This dual-store design has served well through 44 heuristics, but creates three structural limitations:

1. **No graph relationships between MITRE entities and architecture nodes.** Heuristic-to-technique mappings are resolved through flat curated TOML rules or vector similarity over isolated technique descriptions. There is no way to traverse from a detected threat pattern through the MITRE graph (technique -> tactic -> mitigation -> related techniques) to discover contextually relevant mappings.

2. **Vector search is disconnected from graph context.** The current Layer 0 scorer encodes `"{heuristic_name}. {heuristic_description}"` into a query vector and does brute-force cosine similarity against technique embeddings. The composite scorer adds tactic and framework bonuses, but cannot incorporate graph-structural signals (e.g., "this technique's mitigations overlap with controls already declared on the target module").

3. **MITRE knowledge is static after sync.** Techniques, tactics, and mitigations are loaded once into SQLite and queried independently. There is no chunked, retrievable representation of the rich descriptive text within technique and mitigation entries that could support natural-language reasoning about threat applicability.

Neo4j 5.x provides native vector index support (`db.index.vector.createNodeIndex`) and the `neo4j-graphrag` Python package offers a structured GraphRAG pipeline (chunking, embedding, retrieval, generation). Consolidating MITRE knowledge into the same graph database as the architecture model unlocks graph-aware retrieval that combines structural traversal with semantic similarity.

## 2. Goals

1. **Unify storage**: Migrate MITRE ATT&CK/ATLAS data (tactics, techniques, mitigations, and their relationships) into Neo4j alongside the architecture model.
2. **Enable graph-aware vector search**: Use Neo4j's native vector indexes to replace the in-memory NumPy index, allowing combined Cypher + vector queries that traverse MITRE relationships while ranking by semantic similarity.
3. **Improve technique coverage**: Replace the flat composite scorer (Layer 0) with a GraphRAG retriever that can follow mitigation, sub-technique, and tactic edges to discover contextually relevant techniques that pure vector similarity misses.
4. **Maintain determinism**: The curated mapping layer (Layer 1) remains authoritative. GraphRAG enhances the advisory suggestion layer only. Threat report output for a given model + heuristic set remains reproducible.
5. **Backward compatibility**: Existing TOML models, heuristic rules, and test fixtures continue to work. The SQLite store remains available as a fallback/offline mode.

## 3. Current Architecture

```
                  TOML Model
                      |
                      v
              CanonicalModel (Pydantic)
                      |
                      v
            +-------------------+
            |   Neo4j Graph     |      <-- Architecture only
            |  (9 node types,   |
            |   16 rel types)   |
            +-------------------+
                      |
                 50+ Cypher queries
                      |
                      v
              Snapshot Dict (50 keys)
                      |
                      v
            Heuristic Materializers (44 rules)
                      |
                      v
               ThreatRecord[]
                      |
    +--------+--------+--------+
    |        |                 |
    v        v                 v
 Layer 1  Layer 2           Layer 0
 Curated  Tactic-Exp.      Vector Suggestions
 (TOML)   (Optional)       (NumPy brute-force)
    |        |                 |
    |        +---- SQLite -----+
    |        |  (techniques,   |
    |        |   embeddings)   |
    v        v                 v
         TechniqueReference[]
                 |
                 v
           ThreatReport JSON
```

### Current components and limitations

| Component | File | Limitation |
|---|---|---|
| `TechniqueStore` | `src/knowledge/store.py` | SQLite-only; no graph relationships between techniques, tactics, mitigations |
| `TechniqueIndex` | `src/knowledge/index.py` | In-memory dict index; keyword search only (no semantic) |
| `VectorIndex` | `src/knowledge/vector_index.py` | In-memory NumPy; no graph context in similarity results |
| `SentenceTransformerEmbedder` | `src/knowledge/embedder.py` | Embeds technique descriptions only; no chunk-level embeddings |
| `score_suggestions()` | `src/analysis/suggestion_scorer.py` | Composite score = 0.6*vector + 0.25*tactic + 0.15*framework; no mitigation/sub-technique traversal |
| `map_rule_to_techniques()` | `src/analysis/mapping_engine.py` | Layers 2-3 require `TechniqueIndex` singleton; expansion is tactic-flat |
| `GraphQueries` | `src/graph/graph_queries.py` | Architecture-only; no MITRE nodes to join against |

## 4. Target Architecture

```
                  TOML Model
                      |
                      v
              CanonicalModel (Pydantic)
                      |
                      v
     +----------------------------------+
     |         Neo4j Graph              |
     |                                  |
     |  Architecture Sub-Graph          |
     |  (Module, Workflow, Dependency,  |
     |   TrustBoundary, DataStore, ...) |
     |         |                        |
     |    [:MAPS_TO]  [:MITIGATED_BY]   |
     |         |                        |
     |  MITRE Knowledge Sub-Graph       |
     |  (Technique, Tactic, Mitigation, |
     |   TextChunk)                     |
     |         |                        |
     |  Vector Index on TextChunk       |
     |  (native Neo4j vector index)     |
     +----------------------------------+
              |                |
     Cypher Queries     GraphRAG Retriever
     (deterministic)    (semantic + graph)
              |                |
              v                v
        Snapshot Dict    Enhanced Suggestions
              |                |
              v                v
        Materializers    Technique Mappings
              |                |
              v                v
           ThreatReport JSON
```

### 4.1 MITRE Knowledge Graph Schema

New node types added to Neo4j:

```
(:Technique {
    technique_id: string,       // "T1190", "AML.T0016"
    name: string,
    framework: string,          // "ATTACK", "ATLAS"
    domain: string,             // "enterprise", "mobile", "ics"
    description: string,
    is_subtechnique: boolean,
    platforms: [string],
    deprecated: boolean,
    url: string
})

(:Tactic {
    tactic_id: string,          // "TA0001"
    name: string,
    framework: string,
    domain: string,
    shortname: string,          // "initial-access"
    sort_order: integer
})

(:Mitigation {
    mitigation_id: string,      // "M1050"
    name: string,
    framework: string,
    domain: string,
    description: string
})

(:TextChunk {
    chunk_id: string,           // "{entity_id}:chunk:{index}"
    entity_id: string,          // Parent technique/mitigation ID
    entity_type: string,        // "technique" | "mitigation"
    text: string,               // Chunk content
    embedding: [float],         // 384-dim vector (indexed)
    chunk_index: integer,
    token_count: integer
})
```

New relationship types:

```
(:Technique)-[:IN_TACTIC]->(:Tactic)
(:Technique)-[:IS_SUBTECHNIQUE_OF]->(:Technique)
(:Technique)-[:MITIGATED_BY]->(:Mitigation)
(:Mitigation)-[:MITIGATES]->(:Technique)
(:TextChunk)-[:CHUNK_OF]->(:Technique | :Mitigation)
```

### 4.2 Bridge Relationships (Architecture <-> MITRE)

Curated technique mappings currently live in `mapping_rules.toml`. In the unified graph, these become explicit edges:

```
(:HeuristicRule {
    rule_id: string,            // "TH-001"
    name: string,
    severity_hint: string,
    target_type: string
})-[:MAPS_TO {
    tactic: string,
    rationale: string,
    mapping_type: string        // "curated" | "tactic-expansion" | "suggested"
}]->(:Technique)
```

Additionally, NIST 800-53 controls on modules can link to MITRE mitigations:

```
(:Module)-[:IMPLEMENTS_CONTROL {control_id: string}]->(:Mitigation)
```

This is derived at load time by matching `Module.control_functions` entries (e.g., "AC-4") against MITRE mitigation IDs where NIST mappings exist. This bridge enables queries like: *"Which techniques affecting this module are NOT mitigated by any control the module implements?"*

### 4.3 Vector Index

Neo4j 5.x native vector index:

```cypher
CALL db.index.vector.createNodeIndex(
    'textchunk_embedding',    -- index name
    'TextChunk',              -- node label
    'embedding',              -- property name
    384,                      -- dimensions
    'cosine'                  -- similarity function
)
```

Query pattern (semantic search + graph traversal):

```cypher
// Find techniques semantically similar to a heuristic description,
// then traverse to find related mitigations and tactics
CALL db.index.vector.queryNodes('textchunk_embedding', 20, $query_vector)
YIELD node AS chunk, score
MATCH (chunk)-[:CHUNK_OF]->(tech:Technique)
WHERE NOT tech.deprecated
OPTIONAL MATCH (tech)-[:IN_TACTIC]->(tac:Tactic)
OPTIONAL MATCH (tech)-[:MITIGATED_BY]->(mit:Mitigation)
RETURN tech.technique_id, tech.name, tac.shortname, 
       collect(DISTINCT mit.name) AS mitigations,
       score
ORDER BY score DESC
```

## 5. GraphRAG Pipeline

### 5.1 Chunking Strategy

Technique and mitigation descriptions vary from a single sentence to several paragraphs. The chunking strategy:

- **Short descriptions** (< 256 tokens): Single chunk containing the full `"{technique_id} {name}. {description}"` text (same as current `_technique_text()` format).
- **Long descriptions** (>= 256 tokens): Split into overlapping chunks of ~256 tokens with 64-token overlap. Each chunk is prefixed with `"{technique_id} {name}. "` for context anchoring.
- **Mitigation descriptions**: Same strategy, chunked independently. Enables retrieval of mitigations by semantic similarity to threat descriptions.

This replaces the current single-embedding-per-technique approach with finer-grained chunks that capture specific attack steps or detection guidance within long technique descriptions.

### 5.2 Embedding

Use the same `all-MiniLM-L6-v2` model (384 dimensions) for continuity with existing embeddings. The embedder interface (`TextEmbedder` protocol) remains unchanged.

Embedding is performed at sync time:
1. `threatforge sync` fetches ATT&CK/ATLAS bundles (unchanged)
2. New: `KnowledgeGraphLoader` writes Technique/Tactic/Mitigation nodes + relationships to Neo4j
3. New: `ChunkingPipeline` splits descriptions into chunks, embeds them, writes `TextChunk` nodes with `embedding` property
4. Existing: SQLite store updated as before (fallback mode)

### 5.3 Retrieval: GraphRAG-Enhanced Suggestion Scorer

The current `score_suggestions()` function in `suggestion_scorer.py` is replaced by a `GraphRAGScorer` that combines:

1. **Vector retrieval**: Query the Neo4j vector index with the heuristic text embedding to get semantically similar chunks.
2. **Graph expansion**: From retrieved chunks, traverse to parent techniques, then expand along:
   - `[:IN_TACTIC]` to find tactic siblings
   - `[:IS_SUBTECHNIQUE_OF]` to find parent/sibling techniques
   - `[:MITIGATED_BY]` to find mitigation overlap with target module's `control_functions`
3. **Context-aware re-ranking**: Score candidates using signals unavailable to the current flat scorer:
   - **Mitigation gap signal**: Techniques whose mitigations are NOT implemented by the target module score higher (true gaps).
   - **Sub-technique specificity**: Sub-techniques matching a specific parent already in curated mappings score higher.
   - **Graph distance penalty**: Techniques found only via long traversal paths score lower than direct vector hits.

Composite scoring formula (replacing current 0.6/0.25/0.15 weights):

```
composite = w_vector * vector_similarity
          + w_tactic * tactic_overlap_bonus
          + w_framework * framework_match_bonus
          + w_mitigation_gap * mitigation_gap_score
          + w_subtechnique * subtechnique_relevance
```

Where `mitigation_gap_score` is computed as:

```
gap_score = 1.0 - (count of technique mitigations implemented by target module 
                   / total mitigations for technique)
```

### 5.4 Integration Points in the Threat Pipeline

The GraphRAG retriever plugs into two places:

**A. Enhanced Layer 0 (Suggestion Generation)**

Current flow:
```
heuristic text -> SentenceTransformerEmbedder -> VectorIndex.search() -> score_suggestions()
```

New flow:
```
heuristic text -> SentenceTransformerEmbedder -> Neo4j vector query + graph traversal -> GraphRAGScorer
```

This replaces the offline `suggest-mappings` command and the `--map-heuristics` sync flag with higher-quality, graph-contextualized suggestions.

**B. Runtime Threat Enrichment (New Capability)**

After materializers produce `ThreatRecord[]`, a new enrichment step can traverse the MITRE knowledge graph to add:

- **Related techniques**: Techniques linked by shared mitigations or parent/sub-technique relationships to the curated mappings.
- **Applicable mitigations**: Mitigations for mapped techniques that are NOT yet implemented by modules in the affected path.
- **Confidence scoring**: Based on vector similarity + graph evidence strength.

This produces an enriched `ThreatRecord` with a new `suggested_mitigations` field alongside the existing `framework_mappings`.

## 6. Implementation Plan

### Phase A: MITRE Knowledge Graph (Foundation)

**Goal**: Load MITRE data into Neo4j alongside architecture model.

| Step | Description | Files |
|---|---|---|
| A1 | Add Cypher schema for Technique, Tactic, Mitigation nodes | `src/graph/cypher/mitre_constraints.cypher`, `mitre_indexes.cypher` |
| A2 | Create `KnowledgeGraphLoader` to MERGE MITRE nodes + relationships | `src/graph/knowledge_loader.py` (new) |
| A3 | Extend `threatforge sync` to call `KnowledgeGraphLoader` after SQLite sync | `src/knowledge/sync.py` |
| A4 | Add bridge relationship generation (HeuristicRule nodes, MAPS_TO edges from curated TOML) | `src/graph/knowledge_loader.py` |
| A5 | Add IMPLEMENTS_CONTROL bridge (Module -> Mitigation from control_functions) | `src/graph/knowledge_loader.py` |
| A6 | Tests: verify MITRE nodes, relationships, and bridges load correctly | `tests/test_knowledge_loader.py` (new) |

### Phase B: Chunking and Vector Index

**Goal**: Replace SQLite embeddings + NumPy index with Neo4j TextChunk nodes + native vector index.

| Step | Description | Files |
|---|---|---|
| B1 | Create `ChunkingPipeline` (split descriptions, embed, write TextChunk nodes) | `src/knowledge/chunking.py` (new) |
| B2 | Create Neo4j vector index on TextChunk.embedding | `src/graph/cypher/vector_indexes.cypher` (new) |
| B3 | Extend sync to run chunking pipeline after knowledge graph load | `src/knowledge/sync.py` |
| B4 | Create `GraphVectorSearch` — Cypher-based vector query replacing `VectorIndex` | `src/knowledge/graph_vector_search.py` (new) |
| B5 | Tests: verify chunks created, vector index queryable, results match SQLite baseline | `tests/test_chunking.py`, `tests/test_graph_vector_search.py` (new) |

### Phase C: GraphRAG-Enhanced Scoring

**Goal**: Replace flat composite scorer with graph-aware retriever.

| Step | Description | Files |
|---|---|---|
| C1 | Create `GraphRAGScorer` with vector + graph traversal retrieval | `src/analysis/graphrag_scorer.py` (new) |
| C2 | Add mitigation-gap scoring (Cypher query: technique mitigations vs module controls) | `src/analysis/graphrag_scorer.py` |
| C3 | Add sub-technique expansion scoring | `src/analysis/graphrag_scorer.py` |
| C4 | Wire `GraphRAGScorer` into `mapping_engine.py` as enhanced Layer 0 | `src/analysis/mapping_engine.py` |
| C5 | Update `suggest-mappings` CLI command to use GraphRAG scorer | `src/analysis/mapping_writer.py` |
| C6 | Tests: verify improved recall on known technique associations | `tests/test_graphrag_scorer.py` (new) |

### Phase D: Runtime Threat Enrichment

**Goal**: Add graph-based enrichment to threat pipeline output.

| Step | Description | Files |
|---|---|---|
| D1 | Add `suggested_mitigations` field to `ThreatRecord` schema | `src/models/schema/threat_model.py` |
| D2 | Create `ThreatEnricher` — post-materialization graph traversal for related techniques + mitigations | `src/analysis/threat_enricher.py` (new) |
| D3 | Wire enricher into `build_threat_report_from_snapshot()` | `src/analysis/threat_outputs.py` |
| D4 | Tests: verify enriched output, determinism, backward compatibility | `tests/test_threat_enricher.py` (new) |

### Phase E: Cleanup and Migration

**Goal**: Deprecate SQLite-only code paths, update documentation.

| Step | Description | Files |
|---|---|---|
| E1 | Add `--graphrag` / `--legacy` flags to CLI for transition period | `src/cli.py` or equivalent |
| E2 | Mark `VectorIndex`, `TechniqueStore.embeddings` as deprecated | `src/knowledge/vector_index.py`, `src/knowledge/store.py` |
| E3 | Update design documentation | `docs/design_graphrag.md` (this file) |
| E4 | Migration guide for existing deployments | `docs/migration_graphrag.md` (new) |

## 7. New Cypher Query Examples

### 7.1 Semantic technique search with graph expansion

```cypher
// Given a heuristic's embedded text, find relevant techniques with their full context
CALL db.index.vector.queryNodes('textchunk_embedding', $top_k, $query_vector)
YIELD node AS chunk, score
WHERE score > $threshold
MATCH (chunk)-[:CHUNK_OF]->(tech:Technique)
WHERE NOT tech.deprecated
WITH tech, MAX(score) AS best_score
OPTIONAL MATCH (tech)-[:IN_TACTIC]->(tac:Tactic)
OPTIONAL MATCH (tech)-[:MITIGATED_BY]->(mit:Mitigation)
OPTIONAL MATCH (tech)<-[:IS_SUBTECHNIQUE_OF]-(sub:Technique)
RETURN tech.technique_id AS technique_id,
       tech.name AS name,
       tech.framework AS framework,
       collect(DISTINCT tac.shortname) AS tactics,
       collect(DISTINCT mit.name) AS mitigations,
       collect(DISTINCT sub.technique_id) AS subtechniques,
       best_score
ORDER BY best_score DESC
LIMIT $limit
```

### 7.2 Mitigation gap analysis for a specific module

```cypher
// Find techniques mapped to a heuristic rule where the target module
// does NOT implement any of the technique's mitigations
MATCH (rule:HeuristicRule {rule_id: $rule_id})-[:MAPS_TO]->(tech:Technique)
MATCH (tech)-[:MITIGATED_BY]->(mit:Mitigation)
WITH tech, collect(mit.mitigation_id) AS required_mitigations
MATCH (m:Module {id: $module_id})
WITH tech, required_mitigations,
     [mid IN required_mitigations WHERE mid IN m.control_functions] AS implemented
WHERE size(implemented) < size(required_mitigations)
RETURN tech.technique_id AS technique_id,
       tech.name AS technique_name,
       required_mitigations,
       implemented,
       size(required_mitigations) - size(implemented) AS gap_count
ORDER BY gap_count DESC
```

### 7.3 Related techniques via shared mitigations

```cypher
// From a curated technique mapping, discover related techniques
// that share mitigations (potential lateral mappings)
MATCH (tech:Technique {technique_id: $technique_id})-[:MITIGATED_BY]->(mit:Mitigation)
MATCH (mit)<-[:MITIGATED_BY]-(related:Technique)
WHERE related.technique_id <> $technique_id
  AND NOT related.deprecated
WITH related, count(mit) AS shared_mitigations
OPTIONAL MATCH (related)-[:IN_TACTIC]->(tac:Tactic)
RETURN related.technique_id AS technique_id,
       related.name AS name,
       collect(DISTINCT tac.shortname) AS tactics,
       shared_mitigations
ORDER BY shared_mitigations DESC
LIMIT 10
```

### 7.4 End-to-end: Architecture gap -> MITRE technique -> Missing mitigation

```cypher
// For a module detected as missing AC-4 (flow enforcement), find
// all mapped techniques and their unimplemented mitigations
MATCH (m:Module {id: $module_id})
MATCH (rule:HeuristicRule)-[:MAPS_TO]->(tech:Technique)
WHERE rule.rule_id IN $triggered_rules
MATCH (tech)-[:MITIGATED_BY]->(mit:Mitigation)
WHERE NOT mit.mitigation_id IN m.control_functions
RETURN m.id AS module_id,
       tech.technique_id AS technique_id,
       tech.name AS technique_name,
       collect(DISTINCT {
           mitigation_id: mit.mitigation_id,
           name: mit.name
       }) AS unimplemented_mitigations
ORDER BY size(collect(DISTINCT mit.mitigation_id)) DESC
```

## 8. Data Flow: Sync Pipeline (Updated)

```
threatforge sync
    |
    +--> Fetch ATT&CK STIX bundles (unchanged)
    |
    +--> Parse tactics, techniques, mitigations (unchanged)
    |
    +--> SQLite: store.replace_all() (kept for fallback)
    |
    +--> Neo4j: KnowledgeGraphLoader.load_mitre_data()
    |       |
    |       +--> MERGE Tactic nodes
    |       +--> MERGE Technique nodes + [:IN_TACTIC] rels
    |       +--> MERGE [:IS_SUBTECHNIQUE_OF] rels
    |       +--> MERGE Mitigation nodes + [:MITIGATED_BY] rels
    |       +--> MERGE HeuristicRule nodes + [:MAPS_TO] from curated TOML
    |
    +--> Neo4j: ChunkingPipeline.process()
    |       |
    |       +--> Chunk technique descriptions (256 tokens, 64 overlap)
    |       +--> Chunk mitigation descriptions
    |       +--> Embed chunks with SentenceTransformerEmbedder
    |       +--> MERGE TextChunk nodes with embedding property
    |       +--> CREATE/REFRESH vector index
    |
    +--> SQLite: embed_techniques() (kept for fallback)
```

## 9. Data Flow: Threat Pipeline (Updated)

```
threatforge analyze model.toml
    |
    +--> Load CanonicalModel (unchanged)
    |
    +--> Neo4j: GraphLoader.load_model() (unchanged)
    |
    +--> Neo4j: KnowledgeGraphLoader.sync_bridges()
    |       |
    |       +--> MERGE [:IMPLEMENTS_CONTROL] from Module.control_functions
    |
    +--> GraphQueries._build_snapshot() (unchanged, 50 keys)
    |
    +--> Materializers (44 heuristics, unchanged)
    |
    +--> ThreatRecord[] 
    |
    +--> Technique Mapping (Layer 1: curated, unchanged)
    |
    +--> GraphRAG Enhancement (new)
    |       |
    |       +--> For each ThreatRecord:
    |       |     +--> Embed heuristic text
    |       |     +--> Query Neo4j vector index for related chunks
    |       |     +--> Traverse MITRE graph for mitigation gaps
    |       |     +--> Score and rank suggested techniques
    |       |
    |       +--> ThreatEnricher:
    |             +--> Add suggested_mitigations to ThreatRecord
    |             +--> Add related_techniques (advisory)
    |
    +--> ThreatReport JSON (enriched)
```

## 10. Dependencies

### New Python dependencies

```toml
# pyproject.toml additions
dependencies = [
    "neo4j-graphrag>=1.0,<2.0",     # GraphRAG pipeline utilities
]
```

### Neo4j version requirements

- Neo4j 5.11+ required for native vector index support (`db.index.vector.*`)
- Recommended: Neo4j 5.18+ for improved vector query performance

### Existing dependencies (unchanged)

- `neo4j>=5.20,<6.0` (already present)
- `sentence-transformers>=2.2` (optional, in `[suggest]` extra)

## 11. Migration Strategy

### Backward Compatibility

- SQLite knowledge store remains functional. Systems without Neo4j GraphRAG can continue using the current `VectorIndex` + `score_suggestions()` path.
- A configuration flag (`graphrag.enabled = true/false` in a config TOML or environment variable `THREATFORGE_GRAPHRAG=1`) controls whether the GraphRAG path is used.
- Curated TOML mappings remain the source of truth. GraphRAG only enhances the advisory suggestion layer and adds enrichment.
- Threat reports generated with GraphRAG disabled are identical to current output.

### Data Migration

For existing deployments:

1. Run `threatforge sync` — this populates both SQLite (as before) and Neo4j (new) with MITRE data.
2. The sync command is idempotent. Re-running it updates both stores.
3. No schema migration needed for the architecture graph — new node types and relationships are additive.

## 12. Testing Strategy

| Test Area | Approach | Files |
|---|---|---|
| Knowledge graph loading | Unit tests with FakeClient (same pattern as `test_graph_loader.py`) | `tests/test_knowledge_loader.py` |
| Chunking | Unit tests: verify chunk count, overlap, prefix anchoring | `tests/test_chunking.py` |
| Vector search | Integration test: embed known technique, query, verify top-1 | `tests/test_graph_vector_search.py` |
| GraphRAG scorer | Unit tests: mock graph responses, verify composite scoring | `tests/test_graphrag_scorer.py` |
| Threat enrichment | Unit tests: verify suggested_mitigations populated, determinism | `tests/test_threat_enricher.py` |
| Regression | Full pipeline test: same model produces superset of current output | `tests/test_threat_outputs.py` (extended) |
| Fallback mode | Verify SQLite-only path still works when GraphRAG disabled | `tests/test_fallback.py` |

## 13. Risks and Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Neo4j vector index performance at scale | Slow suggestion generation | TextChunk corpus is ~2K nodes (830 techniques * ~2.5 chunks avg); well within brute-force threshold. Monitor and switch to HNSW if needed. |
| Graph query complexity | Slow enrichment step | Cypher queries in sections 7.1-7.4 use targeted MATCH patterns with indexed properties. Add query profiling. |
| Embedding model drift | Inconsistent similarity scores between old and new embeddings | Use same `all-MiniLM-L6-v2` model. Re-embed all chunks on model upgrade. |
| Neo4j unavailability | Threat pipeline blocked | Fallback to SQLite path with `graphrag.enabled = false`. Current pipeline continues to work. |
| MITRE data volume growth | Increased sync time | ATT&CK grows ~5-10% per year. Current ~830 techniques + ~400 mitigations is manageable. Chunking is incremental (hash-based skip). |

## 14. Success Metrics

1. **Technique recall**: For a set of 20 manually validated heuristic-technique pairs not in curated mappings, GraphRAG suggestions should include >= 80% (vs. current ~60% with flat vector search).
2. **Mitigation relevance**: For threat records targeting modules with `control_functions`, suggested mitigations should reference only controls NOT already implemented.
3. **Performance**: Full threat pipeline (44 heuristics + GraphRAG enrichment) completes in < 30 seconds for the example fintech model.
4. **Zero regression**: All existing 257 tests continue to pass with GraphRAG disabled.

## 15. Implementation Record

### Phase A: MITRE Knowledge Graph (completed)

- `src/graph/knowledge_loader.py` — `KnowledgeGraphLoader` with MERGE logic for Technique, Tactic, Mitigation nodes and IN_TACTIC, IS_SUBTECHNIQUE_OF, MITIGATED_BY relationships
- `src/graph/cypher/mitre_constraints.cypher` — uniqueness constraints
- `src/graph/cypher/mitre_indexes.cypher` — performance indexes
- HeuristicRule nodes + MAPS_TO edges from curated TOML
- Module IMPLEMENTS_CONTROL edges from control_functions
- Wired into `threatforge sync --neo4j`
- Tests: `tests/test_knowledge_loader.py` (16 tests)

### Phase B: Chunking and Vector Index (completed)

- `src/knowledge/chunking.py` — `ChunkingPipeline` with overlapping token-based chunking and prefix anchoring
- `src/knowledge/graph_vector_search.py` — `GraphVectorSearch` using `db.index.vector.queryNodes` with graph traversal
- `src/graph/cypher/vector_indexes.cypher` — Neo4j native 384-dim cosine vector index on TextChunk nodes
- Tests: `tests/test_chunking.py` (16 tests), `tests/test_graph_vector_search.py` (12 tests)

### Phase C: GraphRAG-Enhanced Scoring (completed)

- `src/analysis/graphrag_scorer.py` — `GraphRAGScorer` with composite formula: vector (0.45) + tactic overlap (0.15) + framework match (0.10) + mitigation gap (0.20) + sub-technique bonus (0.10)
- `src/analysis/mapping_engine.py` — `graphrag_score_suggestions()` entry point
- CLI: `suggest-mappings --graphrag` flag
- Tests: `tests/test_graphrag_scorer.py` (23 tests)

### Phase D: Runtime Threat Enrichment (completed)

- `src/analysis/threat_enricher.py` — `ThreatEnricher` post-materialization graph traversal
- `src/models/schema/threat_model.py` — `SuggestedMitigation`, `RelatedTechnique` models; new fields on `ThreatRecord`
- Wired into `build_threat_report_from_snapshot()` with opt-in `neo4j_client` parameter
- CLI: `generate-threats --enrich` flag
- Tests: `tests/test_threat_enricher.py` (15 tests)

### Phase E: Cleanup and Migration (completed)

- CLI transition: `--graphrag`/`--enrich` flags + `THREATFORGE_GRAPHRAG=1` env var + `--legacy` override
- Deprecation warnings on `VectorIndex`, `TechniqueStore.upsert_embeddings`, `TechniqueStore.load_all_embeddings`
- Migration guide: `docs/migration_graphrag.md`
- Total new tests across all phases: 82
