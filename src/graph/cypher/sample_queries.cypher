// 1) Which modules are internet exposed?
MATCH (m:Module)
WHERE m.internet_exposed = true
RETURN m.id AS module_id, m.name AS module_name, m.module_type AS module_type
ORDER BY m.id;

// 2) Which high-value objects cross trust boundaries?
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
ORDER BY trust_boundary, object_id;

// 3) Which workflows involve sensitive data?
MATCH (w:Workflow)-[:INVOLVES_OBJECT]->(o:Object)
WHERE o.classification IN ['confidential', 'secret'] OR o.regulated = true
RETURN w.id AS workflow_id,
       w.name AS workflow_name,
       collect(DISTINCT o.id) AS sensitive_objects
ORDER BY workflow_id;

// 4) Which modules have high privilege and external reachability?
MATCH (m:Module)-[:HAS_PRIVILEGE]->(p:PrivilegeLevel)
WHERE p.level >= 2
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
ORDER BY p.level DESC, m.id;

// 5) Which modules depend on AI-relevant services?
MATCH (m:Module)-[:DEPENDS_ON]->(ai:Module)
WHERE ai.ai_relevant = true
RETURN DISTINCT m.id AS module_id,
                ai.id AS ai_module_id
ORDER BY module_id, ai_module_id;

// 6) Which critical workflows should be prioritized for risk review?
MATCH (s:System)-[:HAS_WORKFLOW]->(w:Workflow)-[:INVOLVES_MODULE]->(m:Module)
WHERE s.criticality IN ['high', 'critical']
RETURN w.id AS workflow_id,
       collect(DISTINCT m.id) AS involved_modules,
       s.criticality AS system_criticality
ORDER BY workflow_id;

// 7) Which regulated data objects are affected by workflows/modules?
MATCH (w:Workflow)-[:INVOLVES_OBJECT]->(o:Object)
WHERE o.regulated = true
OPTIONAL MATCH (w)-[:INVOLVES_MODULE]->(m:Module)
RETURN o.id AS regulated_object,
       collect(DISTINCT w.id) AS workflows,
       collect(DISTINCT m.id) AS modules
ORDER BY regulated_object;

// 8) Which low-trust to high-value attack paths exist?
MATCH (src:Module)-[:IN_DOMAIN]->(:SecurityDomain {trust_level: 'low'}),
      (dst:Object)
WHERE dst.classification IN ['confidential', 'secret'] OR dst.regulated = true
MATCH p = (src)-[:DEPENDS_ON*1..5]->(:Module)-[:DEPENDS_ON*0..5]->(:DataStore)-[:STORES]->(dst)
RETURN src.id AS entry_module,
       dst.id AS target_object,
       length(p) AS hops
ORDER BY hops, entry_module, target_object;

// 9) What are all declared dependency edges?
MATCH (s:Module)-[r:DEPENDS_ON]->(t)
RETURN s.id AS source,
       t.id AS target,
       r.relationship AS relationship
ORDER BY source, target;

// 10) Which trust boundaries are modeled?
MATCH (tb:TrustBoundary)-[:CROSSES_FROM]->(from:SecurityDomain),
      (tb)-[:CROSSES_TO]->(to:SecurityDomain)
RETURN tb.id AS trust_boundary,
       from.id AS from_domain,
       to.id AS to_domain
ORDER BY trust_boundary;
