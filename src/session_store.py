from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime
from pathlib import Path

from project_paths import ProjectPaths


def _now() -> str:
    return datetime.now(UTC).isoformat()


@dataclass(frozen=True)
class SessionState:
    session_id: str = "default"
    model_path: str | None = None
    model_id: str | None = None
    manifest_path: str | None = None
    threat_report_path: str | None = None
    risk_report_path: str | None = None
    last_updated: str | None = None


class SessionStoreError(RuntimeError):
    """Raised when the persisted session state is unreadable."""


class SessionStore:
    """Persist the active workspace session shared by CLI and UI."""

    def __init__(self, paths: ProjectPaths):
        self._paths = paths
        self._session_file = paths.current_session_file

    @property
    def paths(self) -> ProjectPaths:
        return self._paths

    def load(self) -> SessionState:
        if not self._session_file.exists():
            return SessionState()
        try:
            payload = json.loads(self._session_file.read_text(encoding="utf-8"))
            return SessionState(**payload)
        except (OSError, json.JSONDecodeError, TypeError) as exc:
            quarantined = self._quarantine_corrupt_file(self._session_file)
            logging.getLogger(__name__).error(
                "Corrupt session state encountered; quarantined file",
                extra={
                    "session_file": str(self._session_file),
                    "quarantined_path": str(quarantined) if quarantined else None,
                },
                exc_info=True,
            )
            return SessionState()

    def save(self, session: SessionState) -> SessionState:
        self._session_file.parent.mkdir(parents=True, exist_ok=True)
        stored = replace(session, last_updated=_now())
        self._session_file.write_text(
            json.dumps(asdict(stored), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return stored

    def clear(self) -> None:
        if self._session_file.exists():
            self._session_file.unlink()

    def update(self, **changes: str | None) -> SessionState:
        current = self.load()
        return self.save(replace(current, **changes))

    def resolve_model_path(self) -> Path | None:
        return self._resolve_path(self.load().model_path)

    def resolve_threat_report_path(self) -> Path | None:
        return self._resolve_path(self.load().threat_report_path)

    def resolve_risk_report_path(self) -> Path | None:
        return self._resolve_path(self.load().risk_report_path)

    def resolve_manifest_path(self) -> Path | None:
        return self._resolve_path(self.load().manifest_path)

    def set_model(self, model_path: str | Path, *, model_id: str | None = None) -> SessionState:
        return self.update(
            model_path=self._serialize_path(model_path),
            model_id=model_id,
            manifest_path=None,
            threat_report_path=None,
            risk_report_path=None,
        )

    def set_manifest(self, manifest_path: str | Path) -> SessionState:
        return self.update(manifest_path=self._serialize_path(manifest_path))

    def set_threat_report(self, threat_report_path: str | Path) -> SessionState:
        return self.update(threat_report_path=self._serialize_path(threat_report_path))

    def set_risk_report(self, risk_report_path: str | Path) -> SessionState:
        return self.update(risk_report_path=self._serialize_path(risk_report_path))

    def set_uploaded_model(self, filename: str, content: bytes) -> Path:
        suffix = Path(filename).suffix or ".toml"
        stem = Path(filename).stem or "uploaded_model"
        target = self._paths.session_models_dir / f"{stem}{suffix}"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        return target

    def _serialize_path(self, value: str | Path) -> str:
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
