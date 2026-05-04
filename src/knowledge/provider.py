from __future__ import annotations

import logging
from pathlib import Path

from project_paths import ProjectPaths

from .index import TechniqueIndex
from .store import TechniqueStore


class KnowledgeProvider:
    """Owns knowledge-store access and a refreshable in-memory technique index."""

    def __init__(self, db_path: Path | str):
        self._db_path = Path(db_path)
        self._index: TechniqueIndex | None = None
        self._version_token: tuple[str, str] | None = None

    @classmethod
    def from_paths(cls, paths: ProjectPaths) -> KnowledgeProvider:
        return cls(paths.knowledge_db)

    @property
    def db_path(self) -> Path:
        return self._db_path

    def get_index(self, *, force_refresh: bool = False) -> TechniqueIndex:
        token = self._read_version_token()
        if force_refresh or self._index is None or self._version_token != token:
            with TechniqueStore(self._db_path) as store:
                self._index = TechniqueIndex(store)
            self._version_token = token
        return self._index

    def maybe_get_index(self) -> TechniqueIndex | None:
        try:
            index = self.get_index()
        except Exception:
            logging.getLogger(__name__).warning(
                "Knowledge index unavailable; continuing without populated index",
                extra={"db_path": str(self._db_path)},
                exc_info=True,
            )
            return None
        return index if index.is_populated() else None

    def invalidate(self) -> None:
        self._index = None
        self._version_token = None

    def _read_version_token(self) -> tuple[str, str]:
        with TechniqueStore(self._db_path) as store:
            return (
                store.get_meta("last_sync_utc", ""),
                store.get_meta("technique_count", "0"),
            )
