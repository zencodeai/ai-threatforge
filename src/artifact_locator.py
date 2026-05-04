from __future__ import annotations

from pathlib import Path


class ArtifactLocator:
    """Locate latest threat/risk artifact files under a base directory."""

    def __init__(self, base_dir: Path) -> None:
        self._base = Path(base_dir)

    def latest(self, folder: str, suffix: str) -> Path | None:
        """Return the most recently modified file matching *suffix in folder, or None."""
        target = self._base / folder
        if not target.exists():
            return None
        candidates = list(target.glob(f"*{suffix}"))
        if not candidates:
            return None
        return max(
            candidates,
            key=lambda path: (path.stat().st_mtime_ns, path.name),
        )

    def latest_threats(self) -> Path | None:
        return self.latest("models/outputs/threats", "_threats.json")

    def latest_risks(self) -> Path | None:
        return self.latest("models/outputs/risks", "_risks.json")
