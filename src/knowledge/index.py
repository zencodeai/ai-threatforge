from __future__ import annotations

import contextvars
import threading
from collections import defaultdict
from pathlib import Path

from .models import Mitigation, Tactic, Technique
from .store import TechniqueStore, default_db_path

_current_index: contextvars.ContextVar[TechniqueIndex | None] = contextvars.ContextVar(
    "technique_index", default=None,
)


class TechniqueIndex:
    """Read-only in-memory index built from TechniqueStore.

    Prefer :func:`get_index` / :func:`set_index` for context-scoped access.
    The class-level :meth:`get` / :meth:`reset` singleton API is kept for
    backward compatibility but delegates to the context-var.
    """

    _lock = threading.Lock()

    def __init__(self, store: TechniqueStore):
        techniques = store.load_all_techniques()
        tactics = store.load_all_tactics()
        mitigations = store.load_all_mitigations()

        self.by_id: dict[str, Technique] = {t.technique_id: t for t in techniques}
        self.by_tactic: dict[str, list[Technique]] = defaultdict(list)
        self.by_platform: dict[str, list[Technique]] = defaultdict(list)
        self.by_framework: dict[str, list[Technique]] = defaultdict(list)
        self.tactic_order: dict[str, list[Tactic]] = defaultdict(list)
        self._mitigations_by_technique: dict[str, list[Mitigation]] = defaultdict(list)

        for tech in techniques:
            if tech.deprecated:
                continue
            self.by_framework[tech.framework].append(tech)
            for tactic in tech.tactics:
                self.by_tactic[tactic].append(tech)
            for platform in tech.platforms:
                self.by_platform[platform].append(tech)

        for tactic in tactics:
            self.tactic_order[tactic.framework].append(tactic)

        for mit in mitigations:
            for tech_id in mit.technique_ids:
                self._mitigations_by_technique[tech_id].append(mit)

        self._all_techniques = techniques
        self._version = store.get_meta("attack_version", "unknown")

    @classmethod
    def get(cls, db_path: Path | None = None) -> TechniqueIndex:
        instance = _current_index.get(None)
        if instance is not None:
            return instance
        with cls._lock:
            # Double-check after acquiring lock
            instance = _current_index.get(None)
            if instance is not None:
                return instance
            path = db_path or default_db_path()
            store = TechniqueStore(path)
            try:
                instance = cls(store)
            finally:
                store.close()
            _current_index.set(instance)
        return instance

    @classmethod
    def reset(cls) -> None:
        """Clear the current context's index — mainly for testing."""
        _current_index.set(None)

    def lookup(self, technique_id: str) -> Technique | None:
        return self.by_id.get(technique_id.upper()) or self.by_id.get(technique_id)

    def techniques_for_tactic(self, tactic_shortname: str) -> list[Technique]:
        return list(self.by_tactic.get(tactic_shortname, []))

    def techniques_for_platform(self, platform: str) -> list[Technique]:
        return list(self.by_platform.get(platform, []))

    def mitigations_for(self, technique_id: str) -> list[Mitigation]:
        return list(self._mitigations_by_technique.get(technique_id, []))

    def search(self, query: str, *, top_k: int = 10) -> list[Technique]:
        terms = {token.lower() for token in query.split() if token.strip()}
        if not terms:
            return []

        scored: list[tuple[int, Technique]] = []
        for tech in self._all_techniques:
            if tech.deprecated:
                continue
            text = f"{tech.technique_id} {tech.name} {tech.description}".lower()
            score = sum(1 for term in terms if term in text)
            if score > 0:
                scored.append((score, tech))

        scored.sort(key=lambda item: (-item[0], item[1].technique_id))
        return [tech for _, tech in scored[:top_k]]

    @property
    def version(self) -> str:
        return self._version

    @property
    def technique_count(self) -> int:
        return len(self.by_id)

    def is_populated(self) -> bool:
        return len(self.by_id) > 0


def get_index() -> TechniqueIndex | None:
    """Return the context-scoped index, or ``None`` if not set."""
    return _current_index.get(None)


def set_index(index: TechniqueIndex | None) -> None:
    """Set (or clear) the context-scoped index."""
    _current_index.set(index)
