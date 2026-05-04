CREATE CONSTRAINT technique_id_unique IF NOT EXISTS
FOR (n:Technique) REQUIRE n.technique_id IS UNIQUE;

CREATE CONSTRAINT tactic_id_unique IF NOT EXISTS
FOR (n:Tactic) REQUIRE n.tactic_id IS UNIQUE;

CREATE CONSTRAINT mitigation_id_unique IF NOT EXISTS
FOR (n:Mitigation) REQUIRE n.mitigation_id IS UNIQUE;

CREATE CONSTRAINT heuristic_rule_id_unique IF NOT EXISTS
FOR (n:HeuristicRule) REQUIRE n.rule_id IS UNIQUE;
