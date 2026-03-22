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
        for domain in model.security_domains:
            self.client.execute_write(
                """
                MERGE (d:SecurityDomain {id: $id})
                SET d.name = $name,
                    d.trust_level = $trust_level
                """,
                {
                    "id": domain.id,
                    "name": domain.name,
                    "trust_level": domain.trust_level,
                },
            )

    def _merge_privileges(self, model: CanonicalModel) -> None:
        for privilege in model.privilege_levels:
            self.client.execute_write(
                """
                MERGE (p:PrivilegeLevel {id: $id})
                SET p.level = $level,
                    p.description = $description
                """,
                {
                    "id": privilege.id,
                    "level": privilege.level,
                    "description": privilege.description,
                },
            )

    def _merge_modules(self, model: CanonicalModel) -> None:
        for module in model.modules:
            self.client.execute_write(
                """
                MERGE (m:Module {id: $id})
                SET m.name = $name,
                    m.module_type = $module_type,
                    m.internet_exposed = $internet_exposed,
                    m.processes_sensitive_data = $processes_sensitive_data,
                    m.ai_relevant = $ai_relevant,
                    m.description = $description
                """,
                {
                    "id": module.id,
                    "name": module.name,
                    "module_type": module.module_type,
                    "internet_exposed": module.internet_exposed,
                    "processes_sensitive_data": module.processes_sensitive_data,
                    "ai_relevant": module.ai_relevant,
                    "description": module.description,
                },
            )
            self.client.execute_write(
                """
                MATCH (m:Module {id: $module_id}), (d:SecurityDomain {id: $domain_id})
                MERGE (m)-[:IN_DOMAIN]->(d)
                """,
                {"module_id": module.id, "domain_id": module.domain},
            )
            self.client.execute_write(
                """
                MATCH (m:Module {id: $module_id}), (p:PrivilegeLevel {id: $privilege_id})
                MERGE (m)-[:HAS_PRIVILEGE]->(p)
                """,
                {"module_id": module.id, "privilege_id": module.privilege},
            )

    def _merge_objects(self, model: CanonicalModel) -> None:
        for obj in model.objects:
            self.client.execute_write(
                """
                MERGE (o:Object {id: $id})
                SET o.name = $name,
                    o.object_type = $object_type,
                    o.classification = $classification,
                    o.regulated = $regulated,
                    o.ai_relevant = $ai_relevant
                """,
                {
                    "id": obj.id,
                    "name": obj.name,
                    "object_type": obj.object_type,
                    "classification": obj.classification,
                    "regulated": obj.regulated,
                    "ai_relevant": obj.ai_relevant,
                },
            )

    def _merge_datastores(self, model: CanonicalModel) -> None:
        for store in model.datastores:
            self.client.execute_write(
                """
                MERGE (d:DataStore {id: $id})
                SET d.name = $name,
                    d.store_type = $store_type,
                    d.ai_relevant = $ai_relevant
                """,
                {
                    "id": store.id,
                    "name": store.name,
                    "store_type": store.store_type,
                    "ai_relevant": store.ai_relevant,
                },
            )
            self.client.execute_write(
                """
                MATCH (ds:DataStore {id: $store_id}), (d:SecurityDomain {id: $domain_id})
                MERGE (ds)-[:IN_DOMAIN]->(d)
                """,
                {"store_id": store.id, "domain_id": store.domain},
            )
            for object_id in store.contains:
                self.client.execute_write(
                    """
                    MATCH (ds:DataStore {id: $store_id}), (o:Object {id: $object_id})
                    MERGE (ds)-[:STORES]->(o)
                    """,
                    {"store_id": store.id, "object_id": object_id},
                )

    def _merge_external_actors(self, model: CanonicalModel) -> None:
        for actor in model.external_actors:
            self.client.execute_write(
                """
                MERGE (a:ExternalActor {id: $id})
                SET a.name = $name,
                    a.actor_type = $actor_type
                """,
                {
                    "id": actor.id,
                    "name": actor.name,
                    "actor_type": actor.actor_type,
                },
            )

    def _merge_workflows(self, model: CanonicalModel) -> None:
        for workflow in model.workflows:
            self.client.execute_write(
                """
                MERGE (w:Workflow {id: $id})
                SET w.name = $name,
                    w.description = $description,
                    w.steps = $steps
                """,
                {
                    "id": workflow.id,
                    "name": workflow.name,
                    "description": workflow.description,
                    "steps": workflow.steps,
                },
            )
            for module_id in workflow.modules:
                self.client.execute_write(
                    """
                    MATCH (w:Workflow {id: $workflow_id}), (m:Module {id: $module_id})
                    MERGE (w)-[:INVOLVES_MODULE]->(m)
                    """,
                    {"workflow_id": workflow.id, "module_id": module_id},
                )
            for object_id in workflow.objects:
                self.client.execute_write(
                    """
                    MATCH (w:Workflow {id: $workflow_id}), (o:Object {id: $object_id})
                    MERGE (w)-[:INVOLVES_OBJECT]->(o)
                    """,
                    {"workflow_id": workflow.id, "object_id": object_id},
                )

    def _merge_trust_boundaries(self, model: CanonicalModel) -> None:
        for boundary in model.trust_boundaries:
            self.client.execute_write(
                """
                MERGE (t:TrustBoundary {id: $id})
                SET t.name = $name
                """,
                {
                    "id": boundary.id,
                    "name": boundary.name,
                },
            )
            self.client.execute_write(
                """
                MATCH (t:TrustBoundary {id: $boundary_id}), (d:SecurityDomain {id: $domain_id})
                MERGE (t)-[:CROSSES_FROM]->(d)
                """,
                {"boundary_id": boundary.id, "domain_id": boundary.from_domain},
            )
            self.client.execute_write(
                """
                MATCH (t:TrustBoundary {id: $boundary_id}), (d:SecurityDomain {id: $domain_id})
                MERGE (t)-[:CROSSES_TO]->(d)
                """,
                {"boundary_id": boundary.id, "domain_id": boundary.to_domain},
            )

    def _merge_dependencies(self, model: CanonicalModel) -> None:
        for dependency in model.dependencies:
            self.client.execute_write(
                """
                MATCH (source:Module {id: $source}),
                      (target {id: $target})
                WHERE target:Module OR target:DataStore
                MERGE (source)-[r:DEPENDS_ON {relationship: $relationship}]->(target)
                """,
                {
                    "source": dependency.source,
                    "target": dependency.target,
                    "relationship": dependency.relationship,
                },
            )

    def _link_system(self, model: CanonicalModel) -> None:
        system_id = model.meta.model_id

        for domain in model.security_domains:
            self.client.execute_write(
                """
                MATCH (s:System {id: $system_id}), (d:SecurityDomain {id: $domain_id})
                MERGE (s)-[:HAS_DOMAIN]->(d)
                """,
                {"system_id": system_id, "domain_id": domain.id},
            )

        for module in model.modules:
            self.client.execute_write(
                """
                MATCH (s:System {id: $system_id}), (m:Module {id: $module_id})
                MERGE (s)-[:HAS_MODULE]->(m)
                """,
                {"system_id": system_id, "module_id": module.id},
            )

        for store in model.datastores:
            self.client.execute_write(
                """
                MATCH (s:System {id: $system_id}), (d:DataStore {id: $store_id})
                MERGE (s)-[:HAS_DATASTORE]->(d)
                """,
                {"system_id": system_id, "store_id": store.id},
            )

        for obj in model.objects:
            self.client.execute_write(
                """
                MATCH (s:System {id: $system_id}), (o:Object {id: $object_id})
                MERGE (s)-[:HAS_OBJECT]->(o)
                """,
                {"system_id": system_id, "object_id": obj.id},
            )

        for workflow in model.workflows:
            self.client.execute_write(
                """
                MATCH (s:System {id: $system_id}), (w:Workflow {id: $workflow_id})
                MERGE (s)-[:HAS_WORKFLOW]->(w)
                """,
                {"system_id": system_id, "workflow_id": workflow.id},
            )

        for boundary in model.trust_boundaries:
            self.client.execute_write(
                """
                MATCH (s:System {id: $system_id}), (t:TrustBoundary {id: $boundary_id})
                MERGE (s)-[:HAS_BOUNDARY]->(t)
                """,
                {"system_id": system_id, "boundary_id": boundary.id},
            )

    def _link_actor_workflows(self, model: CanonicalModel) -> None:
        actor_ids = {actor.id for actor in model.external_actors}
        for workflow in model.workflows:
            for step in workflow.steps:
                source = step.split("->", 1)[0].strip()
                if source in actor_ids:
                    self.client.execute_write(
                        """
                        MATCH (a:ExternalActor {id: $actor_id}), (w:Workflow {id: $workflow_id})
                        MERGE (a)-[:PARTICIPATES_IN]->(w)
                        """,
                        {"actor_id": source, "workflow_id": workflow.id},
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
