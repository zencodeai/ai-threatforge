"""Tests for knowledge.embedder — protocol behavior and import guards."""

from __future__ import annotations

from typing import Sequence
from unittest.mock import patch

import numpy as np
import pytest


class FakeEmbedder:
    """Deterministic embedder for protocol-level testing."""

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
        norms = np.linalg.norm(vecs, axis=1, keepdims=True)
        return vecs / norms


@pytest.fixture()
def embedder():
    return FakeEmbedder()


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


def test_sentence_transformer_import_error():
    from knowledge.embedder import SentenceTransformerEmbedder

    emb = SentenceTransformerEmbedder()
    with patch.dict("sys.modules", {"sentence_transformers": None}):
        with pytest.raises(ImportError, match="sentence-transformers"):
            emb._model = None
            emb._load()
