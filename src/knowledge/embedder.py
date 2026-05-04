"""Text embedding for chunking and graph-backed retrieval."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, Sequence

if TYPE_CHECKING:
    import numpy as np

__all__ = [
    "TextEmbedder",
    "SentenceTransformerEmbedder",
]


# ── Protocol ─────────────────────────────────────────────────────

class TextEmbedder(Protocol):
    """Encode text strings to dense vectors."""

    @property
    def model_name(self) -> str: ...

    @property
    def dimensions(self) -> int: ...

    def encode(self, texts: Sequence[str]) -> np.ndarray:
        """Return array of shape ``(len(texts), self.dimensions)``, dtype float32."""
        ...


# ── Default implementation ───────────────────────────────────────

class SentenceTransformerEmbedder:
    """Embedder backed by ``sentence-transformers``."""

    _model_name = "all-MiniLM-L6-v2"
    _dimensions = 384

    def __init__(self) -> None:
        self._model: object | None = None

    @property
    def model_name(self) -> str:
        return self._model_name

    @property
    def dimensions(self) -> int:
        return self._dimensions

    def _load(self) -> None:
        if self._model is not None:
            return
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError as exc:
            raise ImportError(
                "sentence-transformers is required for embedding. "
                "Install with: pip install -e '.[suggest]'"
            ) from exc
        self._model = SentenceTransformer(self._model_name)

    def encode(self, texts: Sequence[str]) -> np.ndarray:
        self._load()
        return self._model.encode(  # type: ignore[union-attr]
            list(texts),
            normalize_embeddings=True,
            show_progress_bar=False,
            batch_size=128,
        )
