from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from project_paths import ProjectPaths
from session_store import SessionStore


def _now() -> str:
    return datetime.now(UTC).isoformat()


@dataclass(frozen=True)
class AnalysisRunManifest:
    run_id: str
    model_path: str | None = None
    model_id: str | None = None
    threat_report_path: str | None = None
    risk_report_path: str | None = None
    created_at: str | None = None
    last_updated: str | None = None


class AnalysisManifestError(RuntimeError):
    """Raised when an analysis manifest cannot be read or validated."""


class AnalysisManifestStore:
    """Persist and resolve analysis run manifests."""

    def __init__(self, paths: ProjectPaths, *, session_store: SessionStore | None = None):
        self._paths = paths
        self._session_store = session_store or SessionStore(paths)

    def load(self, path: str | Path) -> AnalysisRunManifest:
        manifest_path = Path(path)
        try:
            payload = json.loads(manifest_path.read_text(encoding="utf-8"))
            return AnalysisRunManifest(**payload)
        except (OSError, json.JSONDecodeError, TypeError) as exc:
            quarantined = self._quarantine_corrupt_file(manifest_path)
            logging.getLogger(__name__).error(
                "Corrupt analysis manifest encountered; quarantined file",
                extra={
                    "manifest_path": str(manifest_path),
                    "quarantined_path": str(quarantined) if quarantined else None,
                },
                exc_info=True,
            )
            raise AnalysisManifestError(f"Failed to read manifest at {manifest_path}: {exc}") from exc

    def save(self, manifest: AnalysisRunManifest) -> Path:
        self._paths.manifests_dir.mkdir(parents=True, exist_ok=True)
        stored = replace(
            manifest,
            created_at=manifest.created_at or _now(),
            last_updated=_now(),
        )
        path = self._paths.manifests_dir / f"{stored.run_id}.json"
        path.write_text(json.dumps(asdict(stored), indent=2, sort_keys=True) + "\n", encoding="utf-8")
        self._session_store.set_manifest(path)
        return path

    def create(
        self,
        *,
        model_path: str | Path | None = None,
        model_id: str | None = None,
        threat_report_path: str | Path | None = None,
        risk_report_path: str | Path | None = None,
    ) -> tuple[AnalysisRunManifest, Path]:
        manifest = AnalysisRunManifest(
            run_id=f"analysis-{uuid4().hex[:12]}",
            model_path=self._serialize_path(model_path) if model_path is not None else None,
            model_id=model_id,
            threat_report_path=self._serialize_path(threat_report_path) if threat_report_path is not None else None,
            risk_report_path=self._serialize_path(risk_report_path) if risk_report_path is not None else None,
        )
        path = self.save(manifest)
        return self.load(path), path

    def update(
        self,
        path: str | Path,
        *,
        model_path: str | Path | None = None,
        model_id: str | None = None,
        threat_report_path: str | Path | None = None,
        risk_report_path: str | Path | None = None,
    ) -> tuple[AnalysisRunManifest, Path]:
        current = self.load(path)
        updated = replace(
            current,
            model_path=self._serialize_path(model_path) if model_path is not None else current.model_path,
            model_id=model_id if model_id is not None else current.model_id,
            threat_report_path=self._serialize_path(threat_report_path) if threat_report_path is not None else current.threat_report_path,
            risk_report_path=self._serialize_path(risk_report_path) if risk_report_path is not None else current.risk_report_path,
        )
        saved = self.save(updated)
        return self.load(saved), saved

    def latest(self) -> tuple[AnalysisRunManifest | None, Path | None]:
        if not self._paths.manifests_dir.exists():
            return None, None
        candidates = sorted(
            self._paths.manifests_dir.glob("*.json"),
            key=lambda path: (path.stat().st_mtime_ns, path.name),
            reverse=True,
        )
        for latest in candidates:
            try:
                return self.load(latest), latest
            except AnalysisManifestError:
                continue
        return None, None

    def current(self) -> tuple[AnalysisRunManifest | None, Path | None]:
        current_path = self._session_store.resolve_manifest_path()
        if current_path is not None and current_path.exists():
            try:
                return self.load(current_path), current_path
            except AnalysisManifestError:
                return self.latest()
        return self.latest()

    def current_threat_report_path(self) -> Path | None:
        manifest, _path = self.current()
        return self._resolve_path(manifest.threat_report_path) if manifest else None

    def current_risk_report_path(self) -> Path | None:
        manifest, _path = self.current()
        return self._resolve_path(manifest.risk_report_path) if manifest else None

    def current_metadata(self) -> dict[str, str] | None:
        manifest, path = self.current()
        if manifest is None or path is None:
            return None
        return {
            "run_id": manifest.run_id,
            "manifest_path": self._serialize_path(path),
            "model_id": manifest.model_id or "",
        }

    def _serialize_path(self, value: str | Path | None) -> str | None:
        if value is None:
            return None
        path = Path(value).resolve()
        try:
            return str(path.relative_to(self._paths.root))
        except ValueError:
            return str(path)

    def _resolve_path(self, value: str | None) -> Path | None:
        if not value:
            return None
        path = Path(value)
        if not path.is_absolute():
            path = self._paths.root / path
        return path if path.exists() else None

    @staticmethod
    def _quarantine_corrupt_file(path: Path) -> Path | None:
        if not path.exists():
            return None
        target = path.with_name(f"{path.name}.invalid")
        counter = 1
        while target.exists():
            target = path.with_name(f"{path.name}.invalid.{counter}")
            counter += 1
        path.rename(target)
        return target
