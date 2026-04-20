from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from models.schema.canonical_model import CanonicalModel, load_canonical_model

from .neo4j_client import Neo4jClient, Neo4jConfig


@dataclass
class GraphLoadStats:
    nodes_created: int = 0
    relationships_created: int = 0


class GraphLoader:
    def __init__(self, client: Neo4jClient):
        self.client = client

    @staticmethod
    def _read_cypher_file(path: Path) -> list[str]:
        raw = path.read_text(encoding="utf-8")
        statements = [statement.strip() for statement in raw.split(";")]
        return [statement for statement in statements if statement]

    def apply_schema(self, base_path: Path | None = None) -> None:
        root = base_path or Path(__file__).resolve().parent
        for file_name in ("constraints.cypher", "indexes.cypher"):
            file_path = root / "cypher" / file_name
            for statement in self._read_cypher_file(file_path):
                self.client.execute_write(statement)

    def clear_graph(self) -> None:
        self.client.execute_write("MATCH (n) DETACH DELETE n")

    def load_model(self, model: CanonicalModel) -> GraphLoadStats:
        stats = GraphLoadStats()

        self._merge_system(model)
        self._merge_domains(model)
        self._merge_privileges(model)
        self._merge_modules(model)
        self._merge_objects(model)
        self._merge_datastores(model)
        self._merge_external_actors(model)
        self._merge_workflows(model)
        self._merge_trust_boundaries(model)
        self._merge_dependencies(model)
        self._link_system(model)
        self._link_actor_workflows(model)

        counts = self.client.run_query(
            """
            MATCH (n)
            WITH count(n) AS node_count
            MATCH ()-[r]->()
            RETURN node_count, count(r) AS rel_count
            """
        )[0]
        stats.nodes_created = int(counts["node_count"])
        stats.relationships_created = int(counts["rel_count"])
        return stats

    def _merge_system(self, model: CanonicalModel) -> None:
        self.client.execute_write(
            """
            MERGE (s:System {id: $id})
            SET s.name = $name,
                s.description = $description,
                s.criticality = $criticality,
                s.industry = $industry
            """,
            {
                "id": model.meta.model_id,
                "name": model.system.name,
                "description": model.system.description,
                "criticality": model.system.criticality,
                "industry": model.system.industry,
            },
        )

    def _merge_domains(self, model: CanonicalModel) -> None:
        if not model.security_domains:
            return
        batch = [
            {"id": d.id, "name": d.name, "trust_level": d.trust_level}
            for d in model.security_domains
        ]
        self.client.execute_write(
            """
            UNWIND $batch AS row
            MERGE (d:SecurityDomain {id: row.id})
            SET d.name = row.name,
                d.trust_level = row.trust_level
            """,
            {"batch": batch},
        )

    def _merge_privileges(self, model: CanonicalModel) -> None:
        if not model.privilege_levels:
            return
        batch = [
            {"id": p.id, "level": p.level, "description": p.description}
            for p in model.privilege_levels
        ]
        self.client.execute_write(
            """
            UNWIND $batch AS row
            MERGE (p:PrivilegeLevel {id: row.id})
            SET p.level = row.level,
                p.description = row.description
            """,
            {"batch": batch},
        )

    def _merge_modules(self, model: CanonicalModel) -> None:
        if not model.modules:
            return
        batch = [
            {
                "id": m.id,
                "name": m.name,
                "module_type": m.module_type,
                "internet_exposed": m.internet_exposed,
                "processes_sensitive_data": m.processes_sensitive_data,
                "ai_relevant": m.ai_relevant,
                "description": m.description,
                "domain_id": m.domain,
                "privilege_id": m.privilege,
                "authentication_required": m.authentication_required,
                "input_validation": m.input_validation,
                "rate_limiting": m.rate_limiting,
                "logging_enabled": m.logging_enabled,
                "api_endpoints": m.api_endpoints,
                "deployment_context": m.deployment_context,
                "control_functions": m.control_functions,
            }
            for m in model.modules
        ]
        self.client.execute_write(
            """
            UNWIND $batch AS row
            MERGE (m:Module {id: row.id})
            SET m.name = row.name,
                m.module_type = row.module_type,
                m.internet_exposed = row.internet_exposed,
                m.processes_sensitive_data = row.processes_sensitive_data,
                m.ai_relevant = row.ai_relevant,
                m.description = row.description,
                m.authentication_required = row.authentication_required,
                m.input_validation = row.input_validation,
                m.rate_limiting = row.rate_limiting,
                m.logging_enabled = row.logging_enabled,
                m.api_endpoints = row.api_endpoints,
                m.deployment_context = row.deployment_context,
                m.control_functions = row.control_functions
            """,
            {"batch": batch},
        )
        self.client.execute_write(
            """
            UNWIND $batch AS row
            MATCH (m:Module {id: row.id}), (d:SecurityDomain {id: row.domain_id})
            MERGE (m)-[:IN_DOMAIN]->(d)
            """,
            {"batch": batch},
        )
        self.client.execute_write(
            """
            UNWIND $batch AS row
            MATCH (m:Module {id: row.id}), (p:PrivilegeLevel {id: row.privilege_id})
            MERGE (m)-[:HAS_PRIVILEGE]->(p)
            """,
            {"batch": batch},
        )

    def _merge_objects(self, model: CanonicalModel) -> None:
        if not model.objects:
            return
        batch = [
            {
                "id": o.id,
                "name": o.name,
                "object_type": o.object_type,
                "classification": o.classification,
                "regulated": o.regulated,
                "ai_relevant": o.ai_relevant,
            }
            for o in model.objects
        ]
        self.client.execute_write(
            """
            UNWIND $batch AS row
            MERGE (o:Object {id: row.id})
            SET o.name = row.name,
                o.object_type = row.object_type,
                o.classification = row.classification,
                o.regulated = row.regulated,
                o.ai_relevant = row.ai_relevant
            """,
            {"batch": batch},
        )

    def _merge_datastores(self, model: CanonicalModel) -> None:
        if not model.datastores:
            return
        batch = [
            {
                "id": s.id,
                "name": s.name,
                "store_type": s.store_type,
                "ai_relevant": s.ai_relevant,
                "domain_id": s.domain,
            }
            for s in model.datastores
        ]
        self.client.execute_write(
            """
            UNWIND $batch AS row
            MERGE (d:DataStore {id: row.id})
            SET d.name = row.name,
                d.store_type = row.store_type,
                d.ai_relevant = row.ai_relevant
            """,
            {"batch": batch},
        )
        self.client.execute_write(
            """
            UNWIND $batch AS row
            MATCH (ds:DataStore {id: row.id}), (d:SecurityDomain {id: row.domain_id})
            MERGE (ds)-[:IN_DOMAIN]->(d)
            """,
            {"batch": batch},
        )
        contains_batch = [
            {"store_id": s.id, "object_id": oid}
            for s in model.datastores
            for oid in s.contains
        ]
        if contains_batch:
            self.client.execute_write(
                """
                UNWIND $batch AS row
                MATCH (ds:DataStore {id: row.store_id}), (o:Object {id: row.object_id})
                MERGE (ds)-[:STORES]->(o)
                """,
                {"batch": contains_batch},
            )

    def _merge_external_actors(self, model: CanonicalModel) -> None:
        if not model.external_actors:
            return
        batch = [
            {"id": a.id, "name": a.name, "actor_type": a.actor_type}
            for a in model.external_actors
        ]
        self.client.execute_write(
            """
            UNWIND $batch AS row
            MERGE (a:ExternalActor {id: row.id})
            SET a.name = row.name,
                a.actor_type = row.actor_type
            """,
            {"batch": batch},
        )

    def _merge_workflows(self, model: CanonicalModel) -> None:
        if not model.workflows:
            return
        batch = [
            {
                "id": w.id,
                "name": w.name,
                "description": w.description,
                "steps": w.steps,
            }
            for w in model.workflows
        ]
        self.client.execute_write(
            """
            UNWIND $batch AS row
            MERGE (w:Workflow {id: row.id})
            SET w.name = row.name,
                w.description = row.description,
                w.steps = row.steps
            """,
            {"batch": batch},
        )
        module_batch = [
            {"workflow_id": w.id, "module_id": mid}
            for w in model.workflows
            for mid in w.modules
        ]
        if module_batch:
            self.client.execute_write(
                """
                UNWIND $batch AS row
                MATCH (w:Workflow {id: row.workflow_id}), (m:Module {id: row.module_id})
                MERGE (w)-[:INVOLVES_MODULE]->(m)
                """,
                {"batch": module_batch},
            )
        object_batch = [
            {"workflow_id": w.id, "object_id": oid}
            for w in model.workflows
            for oid in w.objects
        ]
        if object_batch:
            self.client.execute_write(
                """
                UNWIND $batch AS row
                MATCH (w:Workflow {id: row.workflow_id}), (o:Object {id: row.object_id})
                MERGE (w)-[:INVOLVES_OBJECT]->(o)
                """,
                {"batch": object_batch},
            )

    def _merge_trust_boundaries(self, model: CanonicalModel) -> None:
        if not model.trust_boundaries:
            return
        batch = [
            {
                "id": b.id,
                "name": b.name,
                "from_domain": b.from_domain,
                "to_domain": b.to_domain,
            }
            for b in model.trust_boundaries
        ]
        self.client.execute_write(
            """
            UNWIND $batch AS row
            MERGE (t:TrustBoundary {id: row.id})
            SET t.name = row.name
            """,
            {"batch": batch},
        )
        self.client.execute_write(
            """
            UNWIND $batch AS row
            MATCH (t:TrustBoundary {id: row.id}), (d:SecurityDomain {id: row.from_domain})
            MERGE (t)-[:CROSSES_FROM]->(d)
            """,
            {"batch": batch},
        )
        self.client.execute_write(
            """
            UNWIND $batch AS row
            MATCH (t:TrustBoundary {id: row.id}), (d:SecurityDomain {id: row.to_domain})
            MERGE (t)-[:CROSSES_TO]->(d)
            """,
            {"batch": batch},
        )

    def _merge_dependencies(self, model: CanonicalModel) -> None:
        if not model.dependencies:
            return
        batch = [
            {
                "source": d.source,
                "target": d.target,
                "relationship": d.relationship,
                "encryption_in_transit": d.encryption_in_transit,
                "data_flow_direction": d.data_flow_direction,
            }
            for d in model.dependencies
        ]
        self.client.execute_write(
            """
            UNWIND $batch AS row
            MATCH (source:Module {id: row.source}),
                  (target {id: row.target})
            WHERE target:Module OR target:DataStore
            MERGE (source)-[r:DEPENDS_ON {relationship: row.relationship}]->(target)
            SET r.encryption_in_transit = row.encryption_in_transit,
                r.data_flow_direction = row.data_flow_direction
            """,
            {"batch": batch},
        )

    def _link_system(self, model: CanonicalModel) -> None:
        system_id = model.meta.model_id

        if model.security_domains:
            batch = [{"system_id": system_id, "id": d.id} for d in model.security_domains]
            self.client.execute_write(
                """
                UNWIND $batch AS row
                MATCH (s:System {id: row.system_id}), (d:SecurityDomain {id: row.id})
                MERGE (s)-[:HAS_DOMAIN]->(d)
                """,
                {"batch": batch},
            )

        if model.modules:
            batch = [{"system_id": system_id, "id": m.id} for m in model.modules]
            self.client.execute_write(
                """
                UNWIND $batch AS row
                MATCH (s:System {id: row.system_id}), (m:Module {id: row.id})
                MERGE (s)-[:HAS_MODULE]->(m)
                """,
                {"batch": batch},
            )

        if model.datastores:
            batch = [{"system_id": system_id, "id": s.id} for s in model.datastores]
            self.client.execute_write(
                """
                UNWIND $batch AS row
                MATCH (s:System {id: row.system_id}), (d:DataStore {id: row.id})
                MERGE (s)-[:HAS_DATASTORE]->(d)
                """,
                {"batch": batch},
            )

        if model.objects:
            batch = [{"system_id": system_id, "id": o.id} for o in model.objects]
            self.client.execute_write(
                """
                UNWIND $batch AS row
                MATCH (s:System {id: row.system_id}), (o:Object {id: row.id})
                MERGE (s)-[:HAS_OBJECT]->(o)
                """,
                {"batch": batch},
            )

        if model.workflows:
            batch = [{"system_id": system_id, "id": w.id} for w in model.workflows]
            self.client.execute_write(
                """
                UNWIND $batch AS row
                MATCH (s:System {id: row.system_id}), (w:Workflow {id: row.id})
                MERGE (s)-[:HAS_WORKFLOW]->(w)
                """,
                {"batch": batch},
            )

        if model.trust_boundaries:
            batch = [{"system_id": system_id, "id": b.id} for b in model.trust_boundaries]
            self.client.execute_write(
                """
                UNWIND $batch AS row
                MATCH (s:System {id: row.system_id}), (t:TrustBoundary {id: row.id})
                MERGE (s)-[:HAS_BOUNDARY]->(t)
                """,
                {"batch": batch},
            )

    def _link_actor_workflows(self, model: CanonicalModel) -> None:
        actor_ids = {actor.id for actor in model.external_actors}
        pairs = [
            {"actor_id": step.split("->", 1)[0].strip(), "workflow_id": w.id}
            for w in model.workflows
            for step in w.steps
            if step.split("->", 1)[0].strip() in actor_ids
        ]
        if pairs:
            self.client.execute_write(
                """
                UNWIND $batch AS row
                MATCH (a:ExternalActor {id: row.actor_id}), (w:Workflow {id: row.workflow_id})
                MERGE (a)-[:PARTICIPATES_IN]->(w)
                """,
                {"batch": pairs},
            )


def load_model_into_graph(
    model_path: str | Path,
    *,
    clear_graph: bool = False,
    config: Neo4jConfig | None = None,
) -> GraphLoadStats:
    model = load_canonical_model(model_path)
    graph_config = config or Neo4jConfig.from_env()

    with Neo4jClient(graph_config) as client:
        client.verify_connectivity()
        loader = GraphLoader(client)
        loader.apply_schema()
        if clear_graph:
            loader.clear_graph()
        return loader.load_model(model)
