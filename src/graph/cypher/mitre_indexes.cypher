CREATE INDEX technique_framework_idx IF NOT EXISTS
FOR (n:Technique) ON (n.framework);

CREATE INDEX technique_deprecated_idx IF NOT EXISTS
FOR (n:Technique) ON (n.deprecated);

CREATE INDEX tactic_framework_idx IF NOT EXISTS
FOR (n:Tactic) ON (n.framework);

CREATE INDEX tactic_shortname_idx IF NOT EXISTS
FOR (n:Tactic) ON (n.shortname);

CREATE INDEX mitigation_framework_idx IF NOT EXISTS
FOR (n:Mitigation) ON (n.framework);
