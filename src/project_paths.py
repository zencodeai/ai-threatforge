from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ProjectPaths:
    """Centralised path configuration injected at startup."""

    root: Path
    data_dir: Path
    examples_dir: Path
    outputs_dir: Path
    manifests_dir: Path
    threats_dir: Path
    risks_dir: Path
    mapping_rules: Path
    mapping_config: Path
    mapping_suggestions: Path
    knowledge_db: Path
    sessions_dir: Path
    session_models_dir: Path
    current_session_file: Path

    @classmethod
    def from_root(cls, root: Path) -> ProjectPaths:
        root = root.resolve()
        data = root / "data" / "threat_intel"
        outputs = root / "models" / "outputs"
        return cls(
            root=root,
            data_dir=data,
            examples_dir=root / "examples",
            outputs_dir=outputs,
            manifests_dir=outputs / "manifests",
            threats_dir=outputs / "threats",
            risks_dir=outputs / "risks",
            mapping_rules=data / "mapping_rules.toml",
            mapping_config=data / "mapping_config.toml",
            mapping_suggestions=data / "mapping_suggestions.toml",
            knowledge_db=data / "threatforge_kb.db",
            sessions_dir=data / "sessions",
            session_models_dir=data / "sessions" / "models",
            current_session_file=data / "sessions" / "current_session.json",
        )

    @classmethod
    def default(cls) -> ProjectPaths:
        # Resolve from this file's location: src/project_paths.py → repo root is parents[1]
        return cls.from_root(Path(__file__).resolve().parents[1])
