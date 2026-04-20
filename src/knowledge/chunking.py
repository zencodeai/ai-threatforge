"""Chunking pipeline for MITRE technique and mitigation descriptions.

Splits long descriptions into overlapping text chunks, embeds them with
a TextEmbedder, and writes TextChunk nodes with CHUNK_OF relationships
into Neo4j for vector-indexed retrieval.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Sequence

if TYPE_CHECKING:
    import numpy as np

    from graph.neo4j_client import Neo4jClient

    from .embedder import TextEmbedder
    from .models import Mitigation, Technique

__all__ = ["ChunkingPipeline", "ChunkingStats", "chunk_text"]

_log = logging.getLogger(__name__)

# ── Chunking parameters ────────────────────────────────────────

CHUNK_SIZE_TOKENS = 256
CHUNK_OVERLAP_TOKENS = 64
# Rough word-to-token ratio for English text with the MiniLM tokenizer.
# Using word-level splitting avoids a hard dependency on the tokenizer at
# chunk time.  The estimate is conservative (real ratio ~1.3 for MiniLM).
_WORDS_PER_TOKEN = 0.75


def _estimate_tokens(text: str) -> int:
    """Estimate token count from word count."""
    return int(len(text.split()) / _WORDS_PER_TOKEN)


def chunk_text(
    text: str,
    *,
    prefix: str = "",
    chunk_size: int = CHUNK_SIZE_TOKENS,
    overlap: int = CHUNK_OVERLAP_TOKENS,
) -> list[str]:
    """Split *text* into overlapping chunks of approximately *chunk_size* tokens.

    Each chunk is prefixed with *prefix* for context anchoring (e.g.,
    ``"T1190 Exploit Public-Facing Application. "``).

    Short texts (< *chunk_size* tokens) are returned as a single chunk.
    """
    if not text.strip():
        return []

    full = f"{prefix}{text}" if prefix else text
    if _estimate_tokens(full) < chunk_size:
        return [full]

    words = text.split()
    # Convert token counts to approximate word counts
    step_words = max(1, int(chunk_size * _WORDS_PER_TOKEN))
    overlap_words = int(overlap * _WORDS_PER_TOKEN)
    stride = max(1, step_words - overlap_words)

    chunks: list[str] = []
    start = 0
    while start < len(words):
        end = min(start + step_words, len(words))
        segment = " ".join(words[start:end])
        chunks.append(f"{prefix}{segment}" if prefix else segment)
        if end >= len(words):
            break
        start += stride

    return chunks


# ── Pipeline ───────────────────────────────────────────────────


@dataclass
class ChunkingStats:
    technique_chunks: int = 0
    mitigation_chunks: int = 0
    total_embedded: int = 0


class ChunkingPipeline:
    """Chunk MITRE descriptions, embed, and write TextChunk nodes to Neo4j."""

    def __init__(self, client: Neo4jClient, embedder: TextEmbedder) -> None:
        self.client = client
        self.embedder = embedder

    def process(
        self,
        *,
        techniques: Sequence[Technique],
        mitigations: Sequence[Mitigation],
    ) -> ChunkingStats:
        stats = ChunkingStats()

        # Chunk techniques
        tech_records = self._build_chunk_records(
            [
                (t.technique_id, t.name, t.description, "technique")
                for t in techniques
                if not t.deprecated
            ]
        )
        stats.technique_chunks = len(tech_records)

        # Chunk mitigations
        mit_records = self._build_chunk_records(
            [
                (m.mitigation_id, m.name, m.description, "mitigation")
                for m in mitigations
            ]
        )
        stats.mitigation_chunks = len(mit_records)

        all_records = tech_records + mit_records
        if not all_records:
            return stats

        # Embed all chunks
        texts = [r["text"] for r in all_records]
        _log.info(
            "Embedding %d text chunks with %s ...",
            len(texts), self.embedder.model_name,
        )
        vectors = self.embedder.encode(texts)
        stats.total_embedded = len(texts)

        # Attach embeddings to records
        for record, vector in zip(all_records, vectors):
            record["embedding"] = vector.tolist()

        # Write to Neo4j
        self._write_chunks(all_records)
        _log.info("Wrote %d TextChunk nodes to Neo4j.", len(all_records))

        return stats

    def _build_chunk_records(
        self,
        entities: list[tuple[str, str, str, str]],
    ) -> list[dict]:
        """Build chunk record dicts from (entity_id, name, description, entity_type) tuples."""
        records: list[dict] = []
        for entity_id, name, description, entity_type in entities:
            if not description.strip():
                continue
            prefix = f"{entity_id} {name}. "
            chunks = chunk_text(description, prefix=prefix)
            for idx, text in enumerate(chunks):
                chunk_id = self._chunk_id(entity_id, idx)
                records.append({
                    "chunk_id": chunk_id,
                    "entity_id": entity_id,
                    "entity_type": entity_type,
                    "text": text,
                    "chunk_index": idx,
                    "token_count": _estimate_tokens(text),
                })
        return records

    @staticmethod
    def _chunk_id(entity_id: str, index: int) -> str:
        return f"{entity_id}:chunk:{index}"

    def _write_chunks(self, records: list[dict]) -> None:
        """MERGE TextChunk nodes and CHUNK_OF relationships into Neo4j."""
        if not records:
            return

        # Separate technique and mitigation chunks for different MATCH targets
        tech_records = [r for r in records if r["entity_type"] == "technique"]
        mit_records = [r for r in records if r["entity_type"] == "mitigation"]

        if tech_records:
            self.client.execute_write(
                """
                UNWIND $batch AS row
                MERGE (c:TextChunk {chunk_id: row.chunk_id})
                SET c.entity_id = row.entity_id,
                    c.entity_type = row.entity_type,
                    c.text = row.text,
                    c.embedding = row.embedding,
                    c.chunk_index = row.chunk_index,
                    c.token_count = row.token_count
                WITH c, row
                MATCH (t:Technique {technique_id: row.entity_id})
                MERGE (c)-[:CHUNK_OF]->(t)
                """,
                {"batch": tech_records},
            )

        if mit_records:
            self.client.execute_write(
                """
                UNWIND $batch AS row
                MERGE (c:TextChunk {chunk_id: row.chunk_id})
                SET c.entity_id = row.entity_id,
                    c.entity_type = row.entity_type,
                    c.text = row.text,
                    c.embedding = row.embedding,
                    c.chunk_index = row.chunk_index,
                    c.token_count = row.token_count
                WITH c, row
                MATCH (m:Mitigation {mitigation_id: row.entity_id})
                MERGE (c)-[:CHUNK_OF]->(m)
                """,
                {"batch": mit_records},
            )
