CREATE CONSTRAINT system_id_unique IF NOT EXISTS
FOR (n:System) REQUIRE n.id IS UNIQUE;

CREATE CONSTRAINT security_domain_id_unique IF NOT EXISTS
FOR (n:SecurityDomain) REQUIRE n.id IS UNIQUE;

CREATE CONSTRAINT privilege_level_id_unique IF NOT EXISTS
FOR (n:PrivilegeLevel) REQUIRE n.id IS UNIQUE;

CREATE CONSTRAINT module_id_unique IF NOT EXISTS
FOR (n:Module) REQUIRE n.id IS UNIQUE;

CREATE CONSTRAINT object_id_unique IF NOT EXISTS
FOR (n:Object) REQUIRE n.id IS UNIQUE;

CREATE CONSTRAINT datastore_id_unique IF NOT EXISTS
FOR (n:DataStore) REQUIRE n.id IS UNIQUE;

CREATE CONSTRAINT external_actor_id_unique IF NOT EXISTS
FOR (n:ExternalActor) REQUIRE n.id IS UNIQUE;

CREATE CONSTRAINT workflow_id_unique IF NOT EXISTS
FOR (n:Workflow) REQUIRE n.id IS UNIQUE;

CREATE CONSTRAINT trust_boundary_id_unique IF NOT EXISTS
FOR (n:TrustBoundary) REQUIRE n.id IS UNIQUE;
