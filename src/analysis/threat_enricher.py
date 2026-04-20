"""GraphRAG-based threat enrichment — post-materialization graph traversal.

After materializers produce ``ThreatRecord[]``, the :class:`ThreatEnricher`
traverses the MITRE knowledge sub-graph in Neo4j to add:

* **suggested_mitigations**: Mitigations for mapped techniques that are NOT
  implemented by the target module's ``control_functions``.
* **related_techniques**: Techniques linked to curated mappings via shared
  mitigations or parent/sub-technique relationships.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from models.schema.threat_model import RelatedTechnique, SuggestedMitigation

if TYPE_CHECKING:
    from graph.neo4j_client import Neo4jClient
    from models.schema.canonical_model import CanonicalModel
    from models.schema.threat_model import ThreatRecord

__all__ = ["ThreatEnricher"]

_log = logging.getLogger(__name__)


class ThreatEnricher:
    """Enrich threat records with graph-derived mitigations and related techniques."""

    def __init__(self, client: Neo4jClient) -> None:
        self.client = client

    def enrich(
        self,
        threats: list[ThreatRecord],
        model: CanonicalModel,
        *,
        max_mitigations: int = 10,
        max_related: int = 5,
    ) -> list[ThreatRecord]:
        """Enrich threat records in-place and return the same list.

        Parameters
        ----------
        threats:
            Materialized threat records to enrich.
        model:
            The canonical model (used to resolve module control_functions).
        max_mitigations:
            Maximum suggested mitigations per threat record.
        max_related:
            Maximum related techniques per threat record.
        """
        # Build module control_functions lookup
        controls_by_module = self._build_controls_lookup(model)

        for threat in threats:
            technique_ids = [m.technique_id for m in threat.framework_mappings]
            if not technique_ids:
                continue

            module_controls = controls_by_module.get(threat.target_id, set())

            threat.suggested_mitigations = self._suggest_mitigations(
                technique_ids,
                module_controls,
                max_results=max_mitigations,
            )

            threat.related_techniques = self._find_related_techniques(
                technique_ids,
                max_results=max_related,
            )

        return threats

    def _build_controls_lookup(
        self, model: CanonicalModel,
    ) -> dict[str, set[str]]:
        """Map module IDs to their implemented control_functions."""
        lookup: dict[str, set[str]] = {}
        for module in model.modules:
            if module.control_functions:
                lookup[module.id] = set(module.control_functions)
        return lookup

    def _suggest_mitigations(
        self,
        technique_ids: list[str],
        module_controls: set[str],
        *,
        max_results: int = 10,
    ) -> list[SuggestedMitigation]:
        """Find mitigations for mapped techniques not in the module's controls."""
        rows = self.client.run_query(
            """
            UNWIND $technique_ids AS tid
            MATCH (tech:Technique {technique_id: tid})-[:MITIGATED_BY]->(mit:Mitigation)
            RETURN tech.technique_id AS technique_id,
                   tech.name AS technique_name,
                   mit.mitigation_id AS mitigation_id,
                   mit.name AS mitigation_name
            ORDER BY mit.mitigation_id
            """,
            {"technique_ids": technique_ids},
        )

        seen: set[str] = set()
        suggestions: list[SuggestedMitigation] = []

        for row in rows:
            mid = row["mitigation_id"]
            # Skip mitigations already implemented by the module
            if mid in module_controls:
                continue
            # Deduplicate by mitigation_id
            if mid in seen:
                continue
            seen.add(mid)

            suggestions.append(SuggestedMitigation(
                mitigation_id=mid,
                name=row["mitigation_name"],
                technique_id=row["technique_id"],
                technique_name=row["technique_name"],
                rationale=(
                    f"{row['mitigation_name']} mitigates {row['technique_id']} "
                    f"({row['technique_name']}) and is not implemented by the target module."
                ),
            ))

            if len(suggestions) >= max_results:
                break

        return suggestions

    def _find_related_techniques(
        self,
        technique_ids: list[str],
        *,
        max_results: int = 5,
    ) -> list[RelatedTechnique]:
        """Discover techniques related by shared mitigations or sub-technique hierarchy."""
        related: list[RelatedTechnique] = []
        seen: set[str] = set(technique_ids)

        # Shared-mitigation relationships
        shared_rows = self.client.run_query(
            """
            UNWIND $technique_ids AS tid
            MATCH (tech:Technique {technique_id: tid})-[:MITIGATED_BY]->(mit:Mitigation)
            MATCH (mit)<-[:MITIGATED_BY]-(related:Technique)
            WHERE related.technique_id <> tid
              AND NOT related.deprecated
            WITH related, count(DISTINCT mit) AS shared_count
            RETURN related.technique_id AS technique_id,
                   related.name AS technique_name,
                   related.framework AS framework,
                   shared_count
            ORDER BY shared_count DESC
            LIMIT $limit
            """,
            {"technique_ids": technique_ids, "limit": max_results * 2},
        )

        for row in shared_rows:
            tid = row["technique_id"]
            if tid in seen:
                continue
            seen.add(tid)
            related.append(RelatedTechnique(
                technique_id=tid,
                technique_name=row["technique_name"],
                framework=row["framework"],
                relationship="shared-mitigation",
                shared_mitigations=row["shared_count"],
            ))
            if len(related) >= max_results:
                return related

        # Sub-technique / parent relationships
        hierarchy_rows = self.client.run_query(
            """
            UNWIND $technique_ids AS tid
            MATCH (tech:Technique {technique_id: tid})
            OPTIONAL MATCH (tech)<-[:IS_SUBTECHNIQUE_OF]-(sub:Technique)
            WHERE NOT sub.deprecated
            OPTIONAL MATCH (tech)-[:IS_SUBTECHNIQUE_OF]->(parent:Technique)
            WHERE NOT parent.deprecated
            WITH collect(DISTINCT {
                     technique_id: sub.technique_id,
                     technique_name: sub.name,
                     framework: sub.framework,
                     rel: 'subtechnique'
                 }) +
                 collect(DISTINCT {
                     technique_id: parent.technique_id,
                     technique_name: parent.name,
                     framework: parent.framework,
                     rel: 'parent'
                 }) AS candidates
            UNWIND candidates AS c
            WHERE c.technique_id IS NOT NULL
            RETURN DISTINCT c.technique_id AS technique_id,
                   c.technique_name AS technique_name,
                   c.framework AS framework,
                   c.rel AS relationship
            LIMIT $limit
            """,
            {"technique_ids": technique_ids, "limit": max_results - len(related)},
        )

        for row in hierarchy_rows:
            tid = row["technique_id"]
            if tid in seen:
                continue
            seen.add(tid)
            related.append(RelatedTechnique(
                technique_id=tid,
                technique_name=row["technique_name"],
                framework=row["framework"],
                relationship=row["relationship"],
            ))
            if len(related) >= max_results:
                break

        return related
