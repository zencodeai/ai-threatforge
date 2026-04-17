from __future__ import annotations

from pathlib import Path


class ArtifactLocator:
    """Locate latest threat/risk artifact files under a base directory."""

    def __init__(self, base_dir: Path) -> None:
        self._base = Path(base_dir)

    def latest(self, folder: str, suffix: str) -> Path | None:
        """Return the lexicographically last file matching *suffix in folder, or None."""
        target = self._base / folder
        if not target.exists():
            return None
        candidates = sorted(target.glob(f"*{suffix}"))
        return candidates[-1] if candidates else None

    def latest_threats(self) -> Path | None:
        return self.latest("models/outputs/threats", "_threats.json")

    def latest_risks(self) -> Path | None:
        return self.latest("models/outputs/risks", "_risks.json")
