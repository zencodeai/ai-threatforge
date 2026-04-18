"""Tests for knowledge.vector_index — VectorIndex search and ranking."""

from __future__ import annotations

from typing import Sequence

import numpy as np
import pytest

from knowledge.models import Tactic, Technique
from knowledge.store import TechniqueStore


# ── Helpers ──────────────────────────────────────────────────────

class FakeEmbedder:
    _model_name = "fake-test-model"
    _dimensions = 4

    @property
    def model_name(self) -> str:
        return self._model_name

    @property
    def dimensions(self) -> int:
        return self._dimensions

    def encode(self, texts: Sequence[str]) -> np.ndarray:
        rng = np.random.RandomState(42)
        vecs = rng.randn(len(texts), self._dimensions).astype(np.float32)
        norms = np.linalg.norm(vecs, axis=1, keepdims=True)
        return vecs / norms


def _make_store_with_embeddings(tmp_path, n: int = 5):
    """Create a store and insert n synthetic technique embeddings."""
    db = tmp_path / "vec_test.db"
    store = TechniqueStore(db)
    store.replace_all(tactics=[], techniques=[], mitigations=[])

    rng = np.random.RandomState(123)
    ids = [f"T{i:04d}" for i in range(n)]
    vecs = rng.randn(n, 4).astype(np.float32)
    norms = np.linalg.norm(vecs, axis=1, keepdims=True)
    vecs = vecs / norms
    hashes = [f"hash{i}" for i in range(n)]

    store.upsert_embeddings(
        entity_ids=ids,
        entity_type="technique",
        model_name="fake-test-model",
        vectors=vecs,
        text_hashes=hashes,
    )
    return store, ids, vecs


# ── Tests ────────────────────────────────────────────────────────

def test_empty_vector_index(tmp_path):
    from knowledge.vector_index import VectorIndex

    store = TechniqueStore(tmp_path / "empty.db")
    store.replace_all(tactics=[], techniques=[], mitigations=[])
    idx = VectorIndex(store, "fake-test-model")
    assert not idx.is_populated
    assert idx.search(np.zeros(4, dtype=np.float32)) == []
    store.close()


def test_search_returns_ranked_results(tmp_path):
    from knowledge.vector_index import VectorIndex

    store, ids, vecs = _make_store_with_embeddings(tmp_path)
    idx = VectorIndex(store, "fake-test-model")
    assert idx.is_populated

    # Use the first stored vector as the query (should rank itself #1)
    query = vecs[0]
    results = idx.search(query, top_k=3)

    assert len(results) == 3
    assert results[0][0] == ids[0]  # top match is itself
    assert results[0][1] == pytest.approx(1.0, abs=1e-5)  # self-similarity = 1.0
    # Results are in descending score order
    scores = [s for _, s in results]
    assert scores == sorted(scores, reverse=True)
    store.close()


def test_search_respects_top_k(tmp_path):
    from knowledge.vector_index import VectorIndex

    store, ids, vecs = _make_store_with_embeddings(tmp_path, n=10)
    idx = VectorIndex(store, "fake-test-model")

    results = idx.search(vecs[0], top_k=3)
    assert len(results) == 3
    store.close()


def test_search_excludes_ids(tmp_path):
    from knowledge.vector_index import VectorIndex

    store, ids, vecs = _make_store_with_embeddings(tmp_path)
    idx = VectorIndex(store, "fake-test-model")

    results = idx.search(vecs[0], top_k=5, exclude={ids[0]})
    result_ids = {tid for tid, _ in results}
    assert ids[0] not in result_ids
    store.close()


def test_search_with_all_excluded(tmp_path):
    from knowledge.vector_index import VectorIndex

    store, ids, vecs = _make_store_with_embeddings(tmp_path, n=3)
    idx = VectorIndex(store, "fake-test-model")

    results = idx.search(vecs[0], top_k=5, exclude=set(ids))
    assert results == []
    store.close()


def test_model_name_property(tmp_path):
    from knowledge.vector_index import VectorIndex

    store, _, _ = _make_store_with_embeddings(tmp_path)
    idx = VectorIndex(store, "fake-test-model")
    assert idx.model_name == "fake-test-model"
    store.close()
