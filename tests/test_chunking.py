"""Tests for the chunking pipeline — text splitting, embedding, and Neo4j writes."""

from __future__ import annotations

from typing import Sequence

import numpy as np
import pytest

from knowledge.chunking import (
    CHUNK_OVERLAP_TOKENS,
    CHUNK_SIZE_TOKENS,
    ChunkingPipeline,
    chunk_text,
)
from knowledge.models import Mitigation, Technique


# ── chunk_text unit tests ───────────────────────────────────────


class TestChunkText:

    def test_short_text_single_chunk(self) -> None:
        text = "A short description of a technique."
        chunks = chunk_text(text)
        assert len(chunks) == 1
        assert chunks[0] == text

    def test_short_text_with_prefix(self) -> None:
        text = "A short description."
        chunks = chunk_text(text, prefix="T1190 Exploit. ")
        assert len(chunks) == 1
        assert chunks[0] == "T1190 Exploit. A short description."

    def test_empty_text_returns_empty(self) -> None:
        assert chunk_text("") == []
        assert chunk_text("   ") == []

    def test_long_text_produces_multiple_chunks(self) -> None:
        # Generate a long text that will exceed the chunk size
        words = ["word"] * 500  # ~667 tokens at 0.75 words/token
        text = " ".join(words)
        chunks = chunk_text(text)
        assert len(chunks) > 1

    def test_chunks_have_overlap(self) -> None:
        words = ["word"] * 500
        text = " ".join(words)
        chunks = chunk_text(text)
        # Adjacent chunks should share some content (overlap)
        if len(chunks) >= 2:
            words_0 = set(chunks[0].split()[-20:])
            words_1 = set(chunks[1].split()[:20])
            # With overlap, some words should appear in both
            assert len(words_0 & words_1) > 0

    def test_prefix_applied_to_all_chunks(self) -> None:
        words = ["word"] * 500
        text = " ".join(words)
        prefix = "T1190 Exploit Public-Facing App. "
        chunks = chunk_text(text, prefix=prefix)
        for chunk in chunks:
            assert chunk.startswith(prefix)

    def test_custom_chunk_size(self) -> None:
        words = ["word"] * 100
        text = " ".join(words)
        # Very small chunk size should produce many chunks
        chunks = chunk_text(text, chunk_size=20, overlap=5)
        assert len(chunks) > 3

    def test_all_content_covered(self) -> None:
        """Every word from the original text should appear in at least one chunk."""
        words = [f"w{i}" for i in range(300)]
        text = " ".join(words)
        chunks = chunk_text(text)
        all_chunk_words = set()
        for chunk in chunks:
            all_chunk_words.update(chunk.split())
        for word in words:
            assert word in all_chunk_words, f"Missing word: {word}"


# ── FakeClient and FakeEmbedder for pipeline tests ─────────────


class FakeClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict | None]] = []

    def execute_write(self, query: str, parameters: dict | None = None) -> None:
        self.calls.append((query.strip(), parameters))

    def run_query(self, query: str, parameters: dict | None = None) -> list[dict]:
        self.calls.append((query.strip(), parameters))
        return []


class FakeEmbedder:
    model_name = "test-model"
    dimensions = 384

    def encode(self, texts: Sequence[str]) -> np.ndarray:
        return np.random.default_rng(42).random((len(texts), 384)).astype(np.float32)


# ── Sample data ────────────────────────────────────────────────


def _sample_techniques() -> list[Technique]:
    return [
        Technique(
            technique_id="T1190",
            name="Exploit Public-Facing Application",
            framework="ATTACK",
            domain="enterprise",
            description="Adversaries may attempt to exploit a weakness in an Internet-facing host.",
            is_subtechnique=False,
            parent_id=None,
            platforms=("Linux", "Windows"),
            tactics=("initial-access",),
            deprecated=False,
            url="https://attack.mitre.org/techniques/T1190",
        ),
        Technique(
            technique_id="T1078",
            name="Valid Accounts",
            framework="ATTACK",
            domain="enterprise",
            description="Adversaries may obtain and abuse credentials of existing accounts.",
            is_subtechnique=False,
            parent_id=None,
            platforms=("Linux", "Windows", "macOS"),
            tactics=("initial-access",),
            deprecated=False,
            url="https://attack.mitre.org/techniques/T1078",
        ),
        Technique(
            technique_id="T9999",
            name="Deprecated Technique",
            framework="ATTACK",
            domain="enterprise",
            description="This is deprecated.",
            is_subtechnique=False,
            parent_id=None,
            platforms=(),
            tactics=(),
            deprecated=True,
            url="",
        ),
    ]


def _sample_mitigations() -> list[Mitigation]:
    return [
        Mitigation(
            mitigation_id="M1050",
            name="Exploit Protection",
            framework="ATTACK",
            domain="enterprise",
            description="Use exploit protection features to prevent known exploitation techniques.",
            technique_ids=("T1190",),
        ),
    ]


# ── ChunkingPipeline tests ─────────────────────────────────────


class TestChunkingPipeline:

    def test_process_creates_technique_chunks(self) -> None:
        fake = FakeClient()
        pipeline = ChunkingPipeline(fake, FakeEmbedder())  # type: ignore[arg-type]
        stats = pipeline.process(
            techniques=_sample_techniques(),
            mitigations=[],
        )
        # 2 non-deprecated techniques, each short → 1 chunk each
        assert stats.technique_chunks == 2
        assert stats.mitigation_chunks == 0
        assert stats.total_embedded == 2

    def test_process_creates_mitigation_chunks(self) -> None:
        fake = FakeClient()
        pipeline = ChunkingPipeline(fake, FakeEmbedder())  # type: ignore[arg-type]
        stats = pipeline.process(
            techniques=[],
            mitigations=_sample_mitigations(),
        )
        assert stats.mitigation_chunks == 1
        assert stats.total_embedded == 1

    def test_process_skips_deprecated_techniques(self) -> None:
        fake = FakeClient()
        pipeline = ChunkingPipeline(fake, FakeEmbedder())  # type: ignore[arg-type]
        stats = pipeline.process(
            techniques=_sample_techniques(),
            mitigations=[],
        )
        # T9999 is deprecated, should be skipped
        assert stats.technique_chunks == 2

    def test_process_writes_textchunk_nodes(self) -> None:
        fake = FakeClient()
        pipeline = ChunkingPipeline(fake, FakeEmbedder())  # type: ignore[arg-type]
        pipeline.process(
            techniques=_sample_techniques(),
            mitigations=_sample_mitigations(),
        )
        queries = [q for q, _ in fake.calls]
        assert any("MERGE (c:TextChunk {chunk_id: row.chunk_id})" in q for q in queries)
        assert any("MERGE (c)-[:CHUNK_OF]->(t)" in q for q in queries)

    def test_process_writes_chunk_of_mitigation(self) -> None:
        fake = FakeClient()
        pipeline = ChunkingPipeline(fake, FakeEmbedder())  # type: ignore[arg-type]
        pipeline.process(
            techniques=[],
            mitigations=_sample_mitigations(),
        )
        queries = [q for q, _ in fake.calls]
        assert any("MERGE (c)-[:CHUNK_OF]->(m)" in q for q in queries)

    def test_chunk_batch_data_contents(self) -> None:
        fake = FakeClient()
        pipeline = ChunkingPipeline(fake, FakeEmbedder())  # type: ignore[arg-type]
        pipeline.process(
            techniques=_sample_techniques()[:1],  # Just T1190
            mitigations=[],
        )
        # Find the technique chunk write call
        tech_calls = [
            (q, p) for q, p in fake.calls
            if "MERGE (c:TextChunk" in q and p and "batch" in p
            and any(r.get("entity_type") == "technique" for r in p.get("batch", []))
        ]
        assert tech_calls
        batch = tech_calls[0][1]["batch"]
        assert len(batch) == 1
        record = batch[0]
        assert record["chunk_id"] == "T1190:chunk:0"
        assert record["entity_id"] == "T1190"
        assert record["entity_type"] == "technique"
        assert record["chunk_index"] == 0
        assert "T1190 Exploit Public-Facing Application." in record["text"]
        assert isinstance(record["embedding"], list)
        assert len(record["embedding"]) == 384

    def test_empty_input_no_writes(self) -> None:
        fake = FakeClient()
        pipeline = ChunkingPipeline(fake, FakeEmbedder())  # type: ignore[arg-type]
        stats = pipeline.process(techniques=[], mitigations=[])
        assert stats.total_embedded == 0
        assert len(fake.calls) == 0

    def test_process_combined_techniques_and_mitigations(self) -> None:
        fake = FakeClient()
        pipeline = ChunkingPipeline(fake, FakeEmbedder())  # type: ignore[arg-type]
        stats = pipeline.process(
            techniques=_sample_techniques(),
            mitigations=_sample_mitigations(),
        )
        assert stats.technique_chunks == 2
        assert stats.mitigation_chunks == 1
        assert stats.total_embedded == 3
