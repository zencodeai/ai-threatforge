"""Text embedding for technique and heuristic descriptions."""

from __future__ import annotations

import hashlib
import logging
from typing import TYPE_CHECKING, Protocol, Sequence

if TYPE_CHECKING:
    import numpy as np

    from .store import TechniqueStore

__all__ = [
    "TextEmbedder",
    "SentenceTransformerEmbedder",
    "embed_techniques",
]

_log = logging.getLogger(__name__)


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


# ── Sync-time helper ─────────────────────────────────────────────

def _technique_text(technique_id: str, name: str, description: str) -> str:
    """Build the canonical text representation used for embedding."""
    return f"{technique_id} {name}. {description[:500]}"


def embed_techniques(
    store: TechniqueStore,
    embedder: TextEmbedder | None = None,
) -> int:
    """Generate embeddings for all non-deprecated technique descriptions.

    Returns the count of newly embedded (or re-embedded) techniques.
    Skips techniques whose description text has not changed since the last run.
    """
    import numpy as np

    if embedder is None:
        embedder = SentenceTransformerEmbedder()

    techniques = store.load_all_techniques()

    texts: list[str] = []
    ids: list[str] = []
    hashes: list[str] = []

    for tech in techniques:
        if tech.deprecated:
            continue
        source_text = _technique_text(tech.technique_id, tech.name, tech.description)
        text_hash = hashlib.sha256(source_text.encode()).hexdigest()

        existing_hash = store.get_embedding_hash(
            tech.technique_id, "technique", embedder.model_name,
        )
        if existing_hash == text_hash:
            continue

        texts.append(source_text)
        ids.append(tech.technique_id)
        hashes.append(text_hash)

    if not texts:
        _log.info("All technique embeddings up-to-date, nothing to encode.")
        return 0

    _log.info("Encoding %d technique descriptions with %s …", len(texts), embedder.model_name)
    vectors: np.ndarray = embedder.encode(texts)

    store.upsert_embeddings(
        entity_ids=ids,
        entity_type="technique",
        model_name=embedder.model_name,
        vectors=vectors,
        text_hashes=hashes,
    )
    _log.info("Stored %d technique embeddings.", len(texts))
    return len(texts)
