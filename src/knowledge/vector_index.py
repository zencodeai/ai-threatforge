"""In-memory vector index for dense similarity search over technique embeddings."""

from __future__ import annotations

from typing import TYPE_CHECKING

import numpy as np

if TYPE_CHECKING:
    from .store import TechniqueStore

__all__ = ["VectorIndex"]


class VectorIndex:
    """In-memory vector index built from pre-computed embeddings.

    Analogous to :class:`~knowledge.index.TechniqueIndex` but for dense
    vectors.  The corpus is small enough (~830 techniques) that brute-force
    cosine similarity via ``matmul`` is faster than any ANN library.
    """

    def __init__(
        self,
        store: TechniqueStore,
        model_name: str = "all-MiniLM-L6-v2",
    ) -> None:
        ids, blobs = store.load_all_embeddings("technique", model_name)
        self._model_name = model_name
        self._ids: list[str] = ids
        if blobs:
            self._matrix: np.ndarray = np.stack(
                [np.frombuffer(b, dtype=np.float32) for b in blobs]
            )  # (N, dim)
        else:
            self._matrix = np.empty((0, 0), dtype=np.float32)
        self._id_to_idx: dict[str, int] = {tid: i for i, tid in enumerate(ids)}

    def search(
        self,
        query_vector: np.ndarray,
        *,
        top_k: int = 20,
        exclude: set[str] | None = None,
    ) -> list[tuple[str, float]]:
        """Return ``[(technique_id, cosine_similarity), ...]`` in descending order."""
        if self._matrix.size == 0:
            return []
        scores: np.ndarray = self._matrix @ query_vector  # (N,)
        ranked_indices = np.argsort(-scores)
        results: list[tuple[str, float]] = []
        for idx in ranked_indices:
            tid = self._ids[idx]
            if exclude and tid in exclude:
                continue
            results.append((tid, float(scores[idx])))
            if len(results) >= top_k:
                break
        return results

    @property
    def model_name(self) -> str:
        return self._model_name

    @property
    def is_populated(self) -> bool:
        return self._matrix.size > 0
