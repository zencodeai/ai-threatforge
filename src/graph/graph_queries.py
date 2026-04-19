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

    # ── STRIDE expansion queries ─────────────────────────────────

    def unverified_actor_workflows(self) -> list[dict]:
        return self.client.run_query(
            """
            MATCH (a:ExternalActor)-[:PARTICIPATES_IN]->(w:Workflow)
            WHERE NOT EXISTS {
                MATCH (w)-[:INVOLVES_MODULE]->(m:Module)
                WHERE m.module_type = 'identity_service'
            }
            RETURN a.id AS actor_id, a.name AS actor_name, a.actor_type AS actor_type,
                   w.id AS workflow_id, w.name AS workflow_name
            ORDER BY actor_id, workflow_id
            """
        )

    def module_writes_to_sensitive_datastore(self) -> list[dict]:
        return self.client.run_query(
            """
            MATCH (m:Module)-[r:DEPENDS_ON]->(ds:DataStore)-[:STORES]->(o:Object)
            WHERE r.relationship IN ['writes', 'reads_writes']
              AND (o.classification IN ['confidential', 'secret'] OR o.regulated = true)
            RETURN m.id AS module_id, m.name AS module_name,
                   ds.id AS datastore_id, ds.name AS datastore_name,
                   r.relationship AS relationship,
                   collect(DISTINCT o.id) AS sensitive_objects
            ORDER BY module_id, datastore_id
            """
        )

    def exposed_module_fan_out(self) -> list[dict]:
        return self.client.run_query(
            """
            MATCH (m:Module)-[:DEPENDS_ON]->(downstream)
            WHERE m.internet_exposed = true
            WITH m, count(DISTINCT downstream) AS downstream_count,
                 collect(DISTINCT downstream.id) AS downstream_ids
            RETURN m.id AS module_id, m.name AS module_name,
                   downstream_count, downstream_ids
            ORDER BY downstream_count DESC, module_id
            """
        )

    def privilege_escalation_dependencies(self) -> list[dict]:
        return self.client.run_query(
            """
            MATCH (src:Module)-[:HAS_PRIVILEGE]->(sp:PrivilegeLevel),
                  (src)-[:DEPENDS_ON]->(dst:Module)-[:HAS_PRIVILEGE]->(dp:PrivilegeLevel)
            WHERE dp.level > sp.level
            RETURN src.id AS source_module, sp.level AS source_privilege,
                   dst.id AS target_module, dp.level AS target_privilege,
                   dp.level - sp.level AS privilege_gap
            ORDER BY privilege_gap DESC, source_module, target_module
            """
        )

    def cross_domain_datastore_access(self) -> list[dict]:
        return self.client.run_query(
            """
            MATCH (m:Module)-[:DEPENDS_ON]->(ds:DataStore),
                  (m)-[:IN_DOMAIN]->(d:SecurityDomain)
            WITH ds, collect(DISTINCT d.id) AS domains,
                 collect(DISTINCT m.id) AS accessing_modules
            WHERE size(domains) > 1
            RETURN ds.id AS datastore_id, ds.name AS datastore_name,
                   domains, accessing_modules
            ORDER BY datastore_id
            """
        )

    def workflow_module_concentration(self) -> list[dict]:
        return self.client.run_query(
            """
            MATCH (s:System)-[:HAS_WORKFLOW]->(w:Workflow)-[:INVOLVES_MODULE]->(m:Module)
            WHERE s.criticality IN ['high', 'critical']
            WITH m, collect(DISTINCT w.id) AS workflows, count(DISTINCT w) AS workflow_count
            WHERE workflow_count > 1
            RETURN m.id AS module_id, m.name AS module_name,
                   workflow_count, workflows
            ORDER BY workflow_count DESC, module_id
            """
        )

    def regulated_ai_data(self) -> list[dict]:
        return self.client.run_query(
            """
            MATCH (w:Workflow)-[:INVOLVES_OBJECT]->(o:Object),
                  (w)-[:INVOLVES_MODULE]->(m:Module)
            WHERE o.regulated = true AND m.ai_relevant = true
            RETURN DISTINCT o.id AS object_id, o.name AS object_name,
                   m.id AS ai_module_id, m.name AS ai_module_name,
                   w.id AS workflow_id
            ORDER BY object_id, ai_module_id
            """
        )

    # ── CAPEC expansion queries (Phase 2) ───────────────────────────

    def transitive_privilege_escalation(self) -> list[dict]:
        return self.client.run_query(
            """
            MATCH (a:Module)-[:HAS_PRIVILEGE]->(ap:PrivilegeLevel),
                  (a)-[:DEPENDS_ON]->(b:Module)-[:HAS_PRIVILEGE]->(bp:PrivilegeLevel),
                  (b)-[:DEPENDS_ON]->(c:Module)-[:HAS_PRIVILEGE]->(cp:PrivilegeLevel)
            WHERE bp.level > ap.level AND cp.level > bp.level
            RETURN a.id AS source_module, ap.level AS source_privilege,
                   b.id AS intermediate_module, bp.level AS intermediate_privilege,
                   c.id AS target_module, cp.level AS target_privilege,
                   cp.level - ap.level AS total_privilege_gap
            ORDER BY total_privilege_gap DESC, source_module, target_module
            """
        )

    def actor_to_privileged_module(self) -> list[dict]:
        return self.client.run_query(
            """
            MATCH (a:ExternalActor)-[:PARTICIPATES_IN]->(w:Workflow)
                  -[:INVOLVES_MODULE]->(m:Module)-[:HAS_PRIVILEGE]->(p:PrivilegeLevel)
            WHERE p.level >= 2
            RETURN DISTINCT a.id AS actor_id, a.name AS actor_name,
                   a.actor_type AS actor_type,
                   w.id AS workflow_id, w.name AS workflow_name,
                   m.id AS module_id, m.name AS module_name,
                   p.level AS privilege_level
            ORDER BY privilege_level DESC, actor_id, module_id
            """
        )

    def cross_trust_write_access(self) -> list[dict]:
        return self.client.run_query(
            """
            MATCH (m:Module)-[r:DEPENDS_ON]->(ds:DataStore),
                  (m)-[:IN_DOMAIN]->(md:SecurityDomain),
                  (ds)-[:IN_DOMAIN]->(dd:SecurityDomain)
            WHERE r.relationship IN ['writes', 'reads_writes']
              AND md.trust_level = 'low'
              AND dd.trust_level IN ['medium', 'high']
            RETURN m.id AS module_id, m.name AS module_name,
                   md.trust_level AS module_trust,
                   ds.id AS datastore_id, ds.name AS datastore_name,
                   dd.trust_level AS datastore_trust,
                   r.relationship AS relationship
            ORDER BY module_id, datastore_id
            """
        )

    def credential_in_low_trust_workflow(self) -> list[dict]:
        return self.client.run_query(
            """
            MATCH (w:Workflow)-[:INVOLVES_OBJECT]->(o:Object),
                  (w)-[:INVOLVES_MODULE]->(m:Module)-[:IN_DOMAIN]->(d:SecurityDomain)
            WHERE o.object_type = 'credential'
              AND d.trust_level = 'low'
            RETURN DISTINCT o.id AS object_id, o.name AS object_name,
                   w.id AS workflow_id, w.name AS workflow_name,
                   m.id AS module_id, m.name AS module_name,
                   d.id AS domain_id
            ORDER BY object_id, workflow_id, module_id
            """
        )

    def high_fan_in_targets(self) -> list[dict]:
        return self.client.run_query(
            """
            MATCH (src:Module)-[:DEPENDS_ON]->(tgt)
            WHERE tgt:Module OR tgt:DataStore
            WITH tgt, count(DISTINCT src) AS fan_in,
                 collect(DISTINCT src.id) AS dependent_modules,
                 labels(tgt)[0] AS target_label
            WHERE fan_in >= 3
            RETURN tgt.id AS target_id, tgt.name AS target_name,
                   target_label, fan_in, dependent_modules
            ORDER BY fan_in DESC, target_id
            """
        )

    def workflow_trust_span(self) -> list[dict]:
        return self.client.run_query(
            """
            MATCH (w:Workflow)-[:INVOLVES_MODULE]->(m:Module)-[:IN_DOMAIN]->(d:SecurityDomain)
            WITH w, collect(DISTINCT d.trust_level) AS trust_levels,
                 collect(DISTINCT d.id) AS domains
            WHERE 'low' IN trust_levels AND 'high' IN trust_levels
            RETURN w.id AS workflow_id, w.name AS workflow_name,
                   trust_levels, domains
            ORDER BY workflow_id
            """
        )

    def actor_regulated_data_access(self) -> list[dict]:
        return self.client.run_query(
            """
            MATCH (a:ExternalActor)-[:PARTICIPATES_IN]->(w:Workflow)
                  -[:INVOLVES_OBJECT]->(o:Object)
            WHERE o.regulated = true
            RETURN DISTINCT a.id AS actor_id, a.name AS actor_name,
                   a.actor_type AS actor_type,
                   w.id AS workflow_id, w.name AS workflow_name,
                   o.id AS object_id, o.name AS object_name
            ORDER BY actor_id, workflow_id, object_id
            """
        )

    def untrusted_ai_datastore_access(self) -> list[dict]:
        return self.client.run_query(
            """
            MATCH (m:Module)-[:DEPENDS_ON]->(ds:DataStore),
                  (m)-[:IN_DOMAIN]->(md:SecurityDomain)
            WHERE ds.ai_relevant = true
              AND md.trust_level = 'low'
            RETURN m.id AS module_id, m.name AS module_name,
                   md.trust_level AS module_trust,
                   ds.id AS datastore_id, ds.name AS datastore_name
            ORDER BY module_id, datastore_id
            """
        )

    def multi_domain_dependency_chain(self) -> list[dict]:
        return self.client.run_query(
            """
            MATCH (a:Module)-[:IN_DOMAIN]->(d1:SecurityDomain),
                  (a)-[:DEPENDS_ON]->(b)-[:IN_DOMAIN]->(d2:SecurityDomain),
                  (b)-[:DEPENDS_ON]->(c)-[:IN_DOMAIN]->(d3:SecurityDomain)
            WHERE d1.id <> d2.id AND d2.id <> d3.id AND d1.id <> d3.id
            RETURN a.id AS source_module, d1.id AS source_domain,
                   b.id AS intermediate, d2.id AS intermediate_domain,
                   c.id AS target, d3.id AS target_domain
            ORDER BY source_module, target
            """
        )

    def exposed_transitive_datastore_access(self) -> list[dict]:
        return self.client.run_query(
            """
            MATCH (exposed:Module)-[:DEPENDS_ON*1..3]->(ds:DataStore)-[:STORES]->(o:Object)
            WHERE exposed.internet_exposed = true
              AND (o.classification IN ['confidential', 'secret'] OR o.regulated = true)
            RETURN DISTINCT exposed.id AS exposed_module, exposed.name AS exposed_name,
                   ds.id AS datastore_id, ds.name AS datastore_name,
                   collect(DISTINCT o.id) AS sensitive_objects
            ORDER BY exposed_module, datastore_id
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
