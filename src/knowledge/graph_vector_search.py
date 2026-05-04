"""Graph-aware vector search over Neo4j TextChunk nodes.

Replaces the in-memory :class:`~knowledge.vector_index.VectorIndex` with a
Cypher-based query that combines the native Neo4j vector index with graph
traversal to return technique/mitigation context alongside similarity scores.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from graph.neo4j_client import Neo4jClient

__all__ = ["GraphVectorSearch", "VectorSearchResult"]


@dataclass(frozen=True)
class VectorSearchResult:
    """A single result from a graph-aware vector search."""

    technique_id: str
    technique_name: str
    framework: str
    score: float
    tactics: list[str] = field(default_factory=list)
    mitigations: list[str] = field(default_factory=list)
    subtechniques: list[str] = field(default_factory=list)


class GraphVectorSearch:
    """Semantic search backed by Neo4j's native vector index on TextChunk nodes.

    After retrieving the top-k chunks by cosine similarity, traverses the
    MITRE knowledge graph to enrich results with tactics, mitigations, and
    sub-technique relationships.
    """

    INDEX_NAME = "textchunk_embedding"

    def __init__(self, client: Neo4jClient) -> None:
        self.client = client

    def search(
        self,
        query_vector: list[float],
        *,
        top_k: int = 20,
        threshold: float = 0.0,
        exclude: set[str] | None = None,
    ) -> list[VectorSearchResult]:
        """Search for techniques semantically similar to *query_vector*.

        Parameters
        ----------
        query_vector:
            384-dimensional float list (must match the embedding model).
        top_k:
            Maximum number of technique results to return.
        threshold:
            Minimum cosine similarity score (0.0–1.0).
        exclude:
            Technique IDs to exclude from results (e.g., curated mappings).
        """
        # Over-fetch chunks to allow dedup + filtering at the technique level
        fetch_k = top_k * 3

        rows = self.client.run_query(
            """
            CALL db.index.vector.queryNodes($index_name, $fetch_k, $query_vector)
            YIELD node AS chunk, score
            WHERE score >= $threshold
            MATCH (chunk)-[:CHUNK_OF]->(tech:Technique)
            WHERE NOT tech.deprecated
            WITH tech, MAX(score) AS best_score
            ORDER BY best_score DESC
            OPTIONAL MATCH (tech)-[:IN_TACTIC]->(tac:Tactic)
            OPTIONAL MATCH (tech)-[:MITIGATED_BY]->(mit:Mitigation)
            OPTIONAL MATCH (tech)<-[:IS_SUBTECHNIQUE_OF]-(sub:Technique)
            WHERE NOT sub.deprecated
            RETURN tech.technique_id AS technique_id,
                   tech.name AS technique_name,
                   tech.framework AS framework,
                   best_score AS score,
                   collect(DISTINCT tac.shortname) AS tactics,
                   collect(DISTINCT mit.name) AS mitigations,
                   collect(DISTINCT sub.technique_id) AS subtechniques
            ORDER BY score DESC
            """,
            {
                "index_name": self.INDEX_NAME,
                "fetch_k": fetch_k,
                "query_vector": query_vector,
                "threshold": threshold,
            },
        )

        exclude_set = exclude or set()
        results: list[VectorSearchResult] = []
        for row in rows:
            if row["technique_id"] in exclude_set:
                continue
            results.append(VectorSearchResult(
                technique_id=row["technique_id"],
                technique_name=row["technique_name"],
                framework=row["framework"],
                score=row["score"],
                tactics=row["tactics"],
                mitigations=row["mitigations"],
                subtechniques=row["subtechniques"],
            ))
            if len(results) >= top_k:
                break

        return results

    def search_mitigations(
        self,
        query_vector: list[float],
        *,
        top_k: int = 10,
        threshold: float = 0.0,
    ) -> list[dict]:
        """Search for mitigations semantically similar to *query_vector*.

        Returns dicts with mitigation_id, name, score, and techniques list.
        """
        fetch_k = top_k * 3

        rows = self.client.run_query(
            """
            CALL db.index.vector.queryNodes($index_name, $fetch_k, $query_vector)
            YIELD node AS chunk, score
            WHERE score >= $threshold
              AND chunk.entity_type = 'mitigation'
            MATCH (chunk)-[:CHUNK_OF]->(mit:Mitigation)
            WITH mit, MAX(score) AS best_score
            ORDER BY best_score DESC
            OPTIONAL MATCH (tech:Technique)-[:MITIGATED_BY]->(mit)
            WHERE NOT tech.deprecated
            RETURN mit.mitigation_id AS mitigation_id,
                   mit.name AS name,
                   best_score AS score,
                   collect(DISTINCT tech.technique_id) AS techniques
            ORDER BY score DESC
            LIMIT $top_k
            """,
            {
                "index_name": self.INDEX_NAME,
                "fetch_k": fetch_k,
                "query_vector": query_vector,
                "threshold": threshold,
                "top_k": top_k,
            },
        )

        return [
            {
                "mitigation_id": row["mitigation_id"],
                "name": row["name"],
                "score": row["score"],
                "techniques": row["techniques"],
            }
            for row in rows
        ]
