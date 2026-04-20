"""Load MITRE ATT&CK/ATLAS knowledge and heuristic bridge data into Neo4j.

Creates Technique, Tactic, Mitigation, and HeuristicRule nodes with their
relationships (IN_TACTIC, IS_SUBTECHNIQUE_OF, MITIGATED_BY, MAPS_TO) and
bridge edges (IMPLEMENTS_CONTROL) connecting architecture modules to
mitigations via declared control_functions.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Sequence

if TYPE_CHECKING:
    from knowledge.models import Mitigation, Tactic, Technique

    from .neo4j_client import Neo4jClient

_log = logging.getLogger(__name__)


@dataclass
class KnowledgeLoadStats:
    techniques: int = 0
    tactics: int = 0
    mitigations: int = 0
    heuristic_rules: int = 0
    maps_to_edges: int = 0
    implements_control_edges: int = 0
    text_chunks: int = 0


class KnowledgeGraphLoader:
    """Idempotent loader for MITRE knowledge graph data."""

    def __init__(self, client: Neo4jClient) -> None:
        self.client = client

    # ── Schema ──────────────────────────────────────────────────────

    @staticmethod
    def _read_cypher_file(path: Path) -> list[str]:
        raw = path.read_text(encoding="utf-8")
        statements = [s.strip() for s in raw.split(";")]
        return [s for s in statements if s]

    def apply_schema(self, base_path: Path | None = None) -> None:
        root = base_path or Path(__file__).resolve().parent
        for file_name in (
            "mitre_constraints.cypher",
            "mitre_indexes.cypher",
            "vector_indexes.cypher",
        ):
            file_path = root / "cypher" / file_name
            for statement in self._read_cypher_file(file_path):
                self.client.execute_write(statement)

    # ── Core MITRE data ─────────────────────────────────────────────

    def load_mitre_data(
        self,
        *,
        tactics: Sequence[Tactic],
        techniques: Sequence[Technique],
        mitigations: Sequence[Mitigation],
    ) -> KnowledgeLoadStats:
        stats = KnowledgeLoadStats()

        stats.tactics = self._merge_tactics(tactics)
        stats.techniques = self._merge_techniques(techniques)
        self._link_technique_tactics(techniques)
        self._link_subtechniques(techniques)
        stats.mitigations = self._merge_mitigations(mitigations)
        self._link_technique_mitigations(mitigations)

        return stats

    def _merge_tactics(self, tactics: Sequence[Tactic]) -> int:
        if not tactics:
            return 0
        batch = [
            {
                "tactic_id": t.tactic_id,
                "name": t.name,
                "framework": t.framework,
                "domain": t.domain,
                "shortname": t.shortname,
                "sort_order": t.order,
            }
            for t in tactics
        ]
        self.client.execute_write(
            """
            UNWIND $batch AS row
            MERGE (t:Tactic {tactic_id: row.tactic_id})
            SET t.name = row.name,
                t.framework = row.framework,
                t.domain = row.domain,
                t.shortname = row.shortname,
                t.sort_order = row.sort_order
            """,
            {"batch": batch},
        )
        return len(batch)

    def _merge_techniques(self, techniques: Sequence[Technique]) -> int:
        if not techniques:
            return 0
        batch = [
            {
                "technique_id": t.technique_id,
                "name": t.name,
                "framework": t.framework,
                "domain": t.domain,
                "description": t.description,
                "is_subtechnique": t.is_subtechnique,
                "parent_id": t.parent_id,
                "platforms": list(t.platforms),
                "deprecated": t.deprecated,
                "url": t.url,
            }
            for t in techniques
        ]
        self.client.execute_write(
            """
            UNWIND $batch AS row
            MERGE (t:Technique {technique_id: row.technique_id})
            SET t.name = row.name,
                t.framework = row.framework,
                t.domain = row.domain,
                t.description = row.description,
                t.is_subtechnique = row.is_subtechnique,
                t.parent_id = row.parent_id,
                t.platforms = row.platforms,
                t.deprecated = row.deprecated,
                t.url = row.url
            """,
            {"batch": batch},
        )
        return len(batch)

    def _link_technique_tactics(self, techniques: Sequence[Technique]) -> None:
        batch = [
            {"technique_id": t.technique_id, "tactic_shortname": tactic}
            for t in techniques
            for tactic in t.tactics
        ]
        if not batch:
            return
        self.client.execute_write(
            """
            UNWIND $batch AS row
            MATCH (tech:Technique {technique_id: row.technique_id})
            MATCH (tac:Tactic {shortname: row.tactic_shortname})
            MERGE (tech)-[:IN_TACTIC]->(tac)
            """,
            {"batch": batch},
        )

    def _link_subtechniques(self, techniques: Sequence[Technique]) -> None:
        batch = [
            {"technique_id": t.technique_id, "parent_id": t.parent_id}
            for t in techniques
            if t.is_subtechnique and t.parent_id
        ]
        if not batch:
            return
        self.client.execute_write(
            """
            UNWIND $batch AS row
            MATCH (sub:Technique {technique_id: row.technique_id})
            MATCH (parent:Technique {technique_id: row.parent_id})
            MERGE (sub)-[:IS_SUBTECHNIQUE_OF]->(parent)
            """,
            {"batch": batch},
        )

    def _merge_mitigations(self, mitigations: Sequence[Mitigation]) -> int:
        if not mitigations:
            return 0
        batch = [
            {
                "mitigation_id": m.mitigation_id,
                "name": m.name,
                "framework": m.framework,
                "domain": m.domain,
                "description": m.description,
            }
            for m in mitigations
        ]
        self.client.execute_write(
            """
            UNWIND $batch AS row
            MERGE (m:Mitigation {mitigation_id: row.mitigation_id})
            SET m.name = row.name,
                m.framework = row.framework,
                m.domain = row.domain,
                m.description = row.description
            """,
            {"batch": batch},
        )
        return len(batch)

    def _link_technique_mitigations(self, mitigations: Sequence[Mitigation]) -> None:
        batch = [
            {"technique_id": tech_id, "mitigation_id": m.mitigation_id}
            for m in mitigations
            for tech_id in m.technique_ids
        ]
        if not batch:
            return
        self.client.execute_write(
            """
            UNWIND $batch AS row
            MATCH (tech:Technique {technique_id: row.technique_id})
            MATCH (mit:Mitigation {mitigation_id: row.mitigation_id})
            MERGE (tech)-[:MITIGATED_BY]->(mit)
            """,
            {"batch": batch},
        )

    # ── Bridge: HeuristicRule -> Technique (MAPS_TO) ────────────────

    def load_heuristic_bridges(
        self,
        *,
        curated_mappings: Sequence[dict],
        heuristic_rules: Sequence[dict],
    ) -> tuple[int, int]:
        """Create HeuristicRule nodes and MAPS_TO edges from curated mappings.

        Parameters
        ----------
        heuristic_rules:
            Sequence of dicts with keys: rule_id, name, severity_hint, target_type.
        curated_mappings:
            Sequence of dicts with keys: rule_id, technique_id, tactic, rationale,
            mapping_type (default "curated").
        """
        # Merge HeuristicRule nodes
        if not heuristic_rules:
            return 0, 0
        rule_batch = [
            {
                "rule_id": r["rule_id"],
                "name": r["name"],
                "severity_hint": r["severity_hint"],
                "target_type": r["target_type"],
            }
            for r in heuristic_rules
        ]
        self.client.execute_write(
            """
            UNWIND $batch AS row
            MERGE (h:HeuristicRule {rule_id: row.rule_id})
            SET h.name = row.name,
                h.severity_hint = row.severity_hint,
                h.target_type = row.target_type
            """,
            {"batch": rule_batch},
        )

        # Merge MAPS_TO edges
        if not curated_mappings:
            return len(rule_batch), 0
        mapping_batch = [
            {
                "rule_id": m["rule_id"],
                "technique_id": m["technique_id"],
                "tactic": m["tactic"],
                "rationale": m["rationale"],
                "mapping_type": m.get("mapping_type", "curated"),
            }
            for m in curated_mappings
        ]
        self.client.execute_write(
            """
            UNWIND $batch AS row
            MATCH (h:HeuristicRule {rule_id: row.rule_id})
            MATCH (t:Technique {technique_id: row.technique_id})
            MERGE (h)-[r:MAPS_TO {tactic: row.tactic}]->(t)
            SET r.rationale = row.rationale,
                r.mapping_type = row.mapping_type
            """,
            {"batch": mapping_batch},
        )
        return len(rule_batch), len(mapping_batch)

    # ── Bridge: Module -> Mitigation (IMPLEMENTS_CONTROL) ───────────

    def sync_control_bridges(self) -> int:
        """Create IMPLEMENTS_CONTROL edges from Module.control_functions to Mitigations.

        Matches module control_function entries against Mitigation.mitigation_id
        values already in the graph. Returns the number of edges created/merged.
        """
        result = self.client.run_query(
            """
            MATCH (m:Module)
            WHERE size(m.control_functions) > 0
            UNWIND m.control_functions AS ctrl
            MATCH (mit:Mitigation {mitigation_id: ctrl})
            MERGE (m)-[:IMPLEMENTS_CONTROL {control_id: ctrl}]->(mit)
            RETURN count(*) AS edge_count
            """
        )
        count = result[0]["edge_count"] if result else 0
        _log.info("Synced %d IMPLEMENTS_CONTROL bridges.", count)
        return count
