"""Tests for knowledge.embedder — TextEmbedder protocol, embed_techniques()."""

from __future__ import annotations

import hashlib
from typing import Sequence
from unittest.mock import patch

import numpy as np
import pytest

from knowledge.models import Tactic, Technique
from knowledge.store import TechniqueStore


# ── Fake embedder ────────────────────────────────────────────────

class FakeEmbedder:
    """Deterministic embedder for testing (no model download needed)."""

    _model_name = "fake-test-model"
    _dimensions = 8

    @property
    def model_name(self) -> str:
        return self._model_name

    @property
    def dimensions(self) -> int:
        return self._dimensions

    def encode(self, texts: Sequence[str]) -> np.ndarray:
        rng = np.random.RandomState(42)
        vecs = rng.randn(len(texts), self._dimensions).astype(np.float32)
        # L2-normalise
        norms = np.linalg.norm(vecs, axis=1, keepdims=True)
        return vecs / norms


# ── Fixtures ─────────────────────────────────────────────────────

def _sample_tactics() -> list[Tactic]:
    return [
        Tactic("TA0001", "Initial Access", "ATTACK", "enterprise", "initial-access", 0),
    ]


def _sample_techniques() -> list[Technique]:
    return [
        Technique("T1190", "Exploit Public-Facing Application", "ATTACK", "enterprise",
                  "Adversaries may exploit vulnerabilities in internet-facing software.",
                  False, None, ("Linux",), ("initial-access",), False,
                  "https://attack.mitre.org/techniques/T1190"),
        Technique("T1078", "Valid Accounts", "ATTACK", "enterprise",
                  "Adversaries may use valid accounts to maintain access.",
                  False, None, ("Linux", "Windows"), ("initial-access",), False,
                  "https://attack.mitre.org/techniques/T1078"),
        Technique("T9999", "Deprecated Technique", "ATTACK", "enterprise",
                  "This technique is deprecated.",
                  False, None, (), (), True, ""),
    ]


@pytest.fixture()
def populated_store(tmp_path):
    db = tmp_path / "test.db"
    store = TechniqueStore(db)
    store.replace_all(
        tactics=_sample_tactics(),
        techniques=_sample_techniques(),
        mitigations=[],
    )
    yield store
    store.close()


@pytest.fixture()
def embedder():
    return FakeEmbedder()


# ── TextEmbedder protocol ───────────────────────────────────────

def test_fake_embedder_protocol(embedder):
    assert embedder.model_name == "fake-test-model"
    assert embedder.dimensions == 8
    result = embedder.encode(["hello world", "test sentence"])
    assert result.shape == (2, 8)
    assert result.dtype == np.float32


def test_encode_is_l2_normalised(embedder):
    result = embedder.encode(["one", "two", "three"])
    norms = np.linalg.norm(result, axis=1)
    np.testing.assert_allclose(norms, 1.0, atol=1e-6)


# ── embed_techniques ─────────────────────────────────────────────

def test_embed_techniques_stores_embeddings(populated_store, embedder):
    from knowledge.embedder import embed_techniques

    count = embed_techniques(populated_store, embedder)
    # 2 non-deprecated techniques
    assert count == 2
    assert populated_store.embedding_count("technique") == 2


def test_embed_techniques_skips_deprecated(populated_store, embedder):
    from knowledge.embedder import embed_techniques

    embed_techniques(populated_store, embedder)
    ids, blobs = populated_store.load_all_embeddings("technique", embedder.model_name)
    assert "T9999" not in ids


def test_embed_techniques_idempotent(populated_store, embedder):
    from knowledge.embedder import embed_techniques

    first = embed_techniques(populated_store, embedder)
    second = embed_techniques(populated_store, embedder)
    assert first == 2
    assert second == 0  # all hashes match, nothing re-encoded


def test_embed_techniques_re_embeds_on_hash_change(populated_store, embedder):
    from knowledge.embedder import embed_techniques

    embed_techniques(populated_store, embedder)

    # Tamper with the stored hash to simulate a description change
    populated_store._conn.execute(
        "UPDATE embeddings SET text_hash = 'stale' WHERE entity_id = 'T1190'"
    )
    populated_store._conn.commit()

    count = embed_techniques(populated_store, embedder)
    assert count == 1  # only T1190 re-embedded


# ── Store round-trip ─────────────────────────────────────────────

def test_upsert_and_load_embeddings_roundtrip(populated_store, embedder):
    vecs = embedder.encode(["alpha", "beta"])
    populated_store.upsert_embeddings(
        entity_ids=["E1", "E2"],
        entity_type="test",
        model_name="test-model",
        vectors=vecs,
        text_hashes=["h1", "h2"],
    )
    ids, blobs = populated_store.load_all_embeddings("test", "test-model")
    assert ids == ["E1", "E2"]
    loaded = np.stack([np.frombuffer(b, dtype=np.float32) for b in blobs])
    np.testing.assert_allclose(loaded, vecs, atol=1e-6)


def test_get_embedding_hash_returns_none_for_missing(populated_store):
    assert populated_store.get_embedding_hash("X", "y", "z") is None


def test_embedding_count_empty(populated_store):
    assert populated_store.embedding_count() == 0
    assert populated_store.embedding_count("technique") == 0


def test_embedding_count_after_upsert(populated_store, embedder):
    from knowledge.embedder import embed_techniques

    embed_techniques(populated_store, embedder)
    assert populated_store.embedding_count("technique") == 2
    assert populated_store.embedding_count() == 2


# ── SentenceTransformerEmbedder import guard ─────────────────────

def test_sentence_transformer_import_error():
    from knowledge.embedder import SentenceTransformerEmbedder

    emb = SentenceTransformerEmbedder()
    with patch.dict("sys.modules", {"sentence_transformers": None}):
        with pytest.raises(ImportError, match="sentence-transformers"):
            emb._model = None  # force re-load
            emb._load()
