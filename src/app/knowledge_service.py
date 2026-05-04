from __future__ import annotations

import logging
from pathlib import Path

from knowledge.index import TechniqueIndex
from knowledge.provider import KnowledgeProvider
from project_paths import ProjectPaths

from .analysis_service import ServiceError, ServiceResult


class KnowledgeService:
    """Shared knowledge-sync orchestration used by CLI and UI."""

    def __init__(self, *, paths: ProjectPaths | None = None) -> None:
        self.paths = paths or ProjectPaths.default()
        self.knowledge_provider = KnowledgeProvider.from_paths(self.paths)

    def sync(
        self,
        *,
        attack_version: str = "latest",
        atlas_version: str = "latest",
        offline_dir: str | Path | None = None,
        embed: bool = False,
        neo4j: bool = False,
        map_heuristics: bool = False,
        map_threshold: float = 0.40,
        map_top_k: int = 10,
        map_output: Path | None = None,
    ) -> ServiceResult:
        from knowledge.sync import sync

        try:
            counts = sync(
                attack_version=attack_version,
                atlas_version=atlas_version,
                offline_dir=offline_dir,
                db_path=self.paths.knowledge_db,
                embed=embed,
                neo4j=neo4j,
                map_heuristics=map_heuristics,
                map_threshold=map_threshold,
                map_top_k=map_top_k,
                map_output=map_output,
            )
        except Exception as exc:
            logging.getLogger(__name__).exception(
                "Knowledge sync failed",
                extra={"step": "sync"},
            )
            return ServiceResult(
                ok=False,
                stdout="",
                stderr=f"FAILED [KNOWLEDGE_SYNC_FAILED] sync: {exc}",
                returncode=1,
                error=ServiceError(
                    code="KNOWLEDGE_SYNC_FAILED",
                    message=str(exc),
                    step="sync",
                    exception_type=type(exc).__name__,
                ),
            )

        # Invalidate both the injected provider cache and the legacy context cache.
        self.knowledge_provider.invalidate()
        TechniqueIndex.reset()

        lines = [
            "SYNC COMPLETE",
            f"  tactics:     {counts['tactics']}",
            f"  techniques:  {counts['techniques']}",
            f"  mitigations: {counts['mitigations']}",
        ]
        if "neo4j_techniques" in counts:
            lines.extend([
                "  neo4j:",
                f"    techniques:  {counts['neo4j_techniques']}",
                f"    tactics:     {counts['neo4j_tactics']}",
                f"    mitigations: {counts['neo4j_mitigations']}",
                f"    rules:       {counts['neo4j_heuristic_rules']}",
                f"    maps_to:     {counts['neo4j_maps_to']}",
                f"    ctrl_bridges:{counts['neo4j_implements_control']}",
            ])
            if counts.get("neo4j_text_chunks"):
                lines.append(f"    text_chunks: {counts['neo4j_text_chunks']}")
        if "suggestions" in counts:
            lines.append(f"  suggestions: {counts['suggestions']}")

        return ServiceResult(
            ok=True,
            stdout="\n".join(lines),
            returncode=0,
            data={"counts": counts},
        )

    def status(self) -> dict[str, str]:
        from knowledge.sync import sync_status

        return sync_status(
            db_path=self.paths.knowledge_db,
            suggestions_path=self.paths.mapping_suggestions,
        )
