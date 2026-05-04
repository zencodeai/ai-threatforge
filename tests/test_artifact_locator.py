from __future__ import annotations

import os
from pathlib import Path

from artifact_locator import ArtifactLocator


def test_latest_prefers_most_recent_mtime_over_lexicographic_order(tmp_path: Path) -> None:
    target = tmp_path / "models" / "outputs" / "threats"
    target.mkdir(parents=True, exist_ok=True)

    newer = target / "aaa_threats.json"
    newer.write_text("{}", encoding="utf-8")

    older = target / "zzz_threats.json"
    older.write_text("{}", encoding="utf-8")

    os.utime(older, (1, 1))
    os.utime(newer, (2, 2))

    latest = ArtifactLocator(tmp_path).latest_threats()

    assert latest == newer
