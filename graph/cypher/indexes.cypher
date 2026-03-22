CREATE INDEX module_internet_exposed_idx IF NOT EXISTS
FOR (n:Module) ON (n.internet_exposed);

CREATE INDEX module_ai_relevant_idx IF NOT EXISTS
FOR (n:Module) ON (n.ai_relevant);

CREATE INDEX object_classification_idx IF NOT EXISTS
FOR (n:Object) ON (n.classification);

CREATE INDEX object_regulated_idx IF NOT EXISTS
FOR (n:Object) ON (n.regulated);

CREATE INDEX workflow_id_lookup_idx IF NOT EXISTS
FOR (n:Workflow) ON (n.id);
