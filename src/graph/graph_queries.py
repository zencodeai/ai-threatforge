from __future__ import annotations

from pathlib import Path

from .neo4j_client import Neo4jClient, Neo4jConfig


class GraphQueries:
    def __init__(self, client: Neo4jClient):
        self.client = client

    def internet_exposed_modules(self) -> list[dict]:
        return self.client.run_query(
            """
            MATCH (m:Module)
            WHERE m.internet_exposed = true
            RETURN m.id AS module_id, m.name AS module_name, m.module_type AS module_type
            ORDER BY m.id
            """
        )

    def high_value_objects_crossing_boundaries(self) -> list[dict]:
        return self.client.run_query(
            """
            MATCH (tb:TrustBoundary)-[:CROSSES_FROM]->(from:SecurityDomain),
                  (tb)-[:CROSSES_TO]->(to:SecurityDomain),
                  (src:Module)-[:IN_DOMAIN]->(from),
                  (src)-[:DEPENDS_ON]->(dst),
                  (dst)-[:IN_DOMAIN]->(to),
                  (dst)<-[:INVOLVES_MODULE]-(w:Workflow)-[:INVOLVES_OBJECT]->(o:Object)
            WHERE o.classification IN ['confidential', 'secret'] OR o.regulated = true
            RETURN DISTINCT tb.id AS trust_boundary,
                            o.id AS object_id,
                            o.classification AS classification,
                            o.regulated AS regulated,
                            w.id AS workflow_id
            ORDER BY trust_boundary, object_id
            """
        )

    def workflows_involving_sensitive_data(self) -> list[dict]:
        return self.client.run_query(
            """
            MATCH (w:Workflow)-[:INVOLVES_OBJECT]->(o:Object)
            WHERE o.classification IN ['confidential', 'secret'] OR o.regulated = true
            RETURN w.id AS workflow_id,
                   w.name AS workflow_name,
                   collect(DISTINCT o.id) AS sensitive_objects
            ORDER BY workflow_id
            """
        )

    def high_privilege_externally_reachable_modules(self, min_level: int = 2) -> list[dict]:
        return self.client.run_query(
            """
            MATCH (m:Module)-[:HAS_PRIVILEGE]->(p:PrivilegeLevel)
            WHERE p.level >= $min_level
              AND (
                m.internet_exposed = true
                OR EXISTS {
                    MATCH (ext:ExternalActor)-[:PARTICIPATES_IN]->(:Workflow)-[:INVOLVES_MODULE]->(m)
                }
              )
            RETURN DISTINCT m.id AS module_id,
                            p.id AS privilege_id,
                            p.level AS privilege_level,
                            m.internet_exposed AS internet_exposed
            ORDER BY p.level DESC, m.id
            """,
            {"min_level": min_level},
        )

    def modules_depending_on_ai_services(self) -> list[dict]:
        return self.client.run_query(
            """
            MATCH (m:Module)-[:DEPENDS_ON]->(ai:Module)
            WHERE ai.ai_relevant = true
            RETURN DISTINCT m.id AS module_id,
                            ai.id AS ai_module_id
            ORDER BY module_id, ai_module_id
            """
        )

    def risks_targeting_critical_workflows_view(self) -> list[dict]:
        return self.client.run_query(
            """
            MATCH (s:System)-[:HAS_WORKFLOW]->(w:Workflow)-[:INVOLVES_MODULE]->(m:Module)
            WHERE s.criticality IN ['high', 'critical']
            RETURN w.id AS workflow_id,
                   collect(DISTINCT m.id) AS involved_modules,
                   s.criticality AS system_criticality
            ORDER BY workflow_id
            """
        )

    def threats_affecting_regulated_data_view(self) -> list[dict]:
        return self.client.run_query(
            """
            MATCH (w:Workflow)-[:INVOLVES_OBJECT]->(o:Object)
            WHERE o.regulated = true
            OPTIONAL MATCH (w)-[:INVOLVES_MODULE]->(m:Module)
            RETURN o.id AS regulated_object,
                   collect(DISTINCT w.id) AS workflows,
                   collect(DISTINCT m.id) AS modules
            ORDER BY regulated_object
            """
        )

    def low_to_high_trust_attack_paths(self, max_depth: int = 5) -> list[dict]:
        return self.client.run_query(
            """
            MATCH (src:Module)-[:IN_DOMAIN]->(:SecurityDomain {trust_level: 'low'}),
                  (dst:Object)
            WHERE dst.classification IN ['confidential', 'secret'] OR dst.regulated = true
            MATCH p = (src)-[:DEPENDS_ON*1..5]->(:Module)-[:DEPENDS_ON*0..5]->(:DataStore)-[:STORES]->(dst)
            WHERE length(p) <= $max_depth
            RETURN src.id AS entry_module,
                   dst.id AS target_object,
                   length(p) AS hops
            ORDER BY hops, entry_module, target_object
            """,
            {"max_depth": max_depth},
        )

    def dependency_edges(self) -> list[dict]:
        return self.client.run_query(
            """
            MATCH (s:Module)-[r:DEPENDS_ON]->(t)
            RETURN s.id AS source,
                   t.id AS target,
                   r.relationship AS relationship
            ORDER BY source, target
            """
        )

    def trust_boundary_crossings(self) -> list[dict]:
        return self.client.run_query(
            """
            MATCH (tb:TrustBoundary)-[:CROSSES_FROM]->(from:SecurityDomain),
                  (tb)-[:CROSSES_TO]->(to:SecurityDomain)
            RETURN tb.id AS trust_boundary,
                   from.id AS from_domain,
                   to.id AS to_domain
            ORDER BY trust_boundary
            """
        )


def load_sample_queries(path: Path | None = None) -> list[str]:
    root = path or Path(__file__).resolve().parent / "cypher" / "sample_queries.cypher"
    raw = root.read_text(encoding="utf-8")
    return [statement.strip() for statement in raw.split(";") if statement.strip()]


def create_queries_from_env() -> GraphQueries:
    config = Neo4jConfig.from_env()
    client = Neo4jClient(config)
    return GraphQueries(client)
