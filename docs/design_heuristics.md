# Design: Heuristic Expansion Strategy

> Scope: Analysis of current heuristic limitations, framework-driven expansion approach, and model enrichment roadmap

---

## 1. Current State

The threat engine runs **6 deterministic heuristics** (TH-001 through TH-006), each detecting a structural pattern in the architecture graph. Heuristics are auto-discovered from the `src/analysis/heuristics/` package in two formats:

- **TOML rules** (`rules/th_*.toml`) — config-driven definitions processed by the `GenericMaterializer` engine. Preferred for new heuristics that follow standard patterns (iteration, filtering, cross-reference, join).
- **Python modules** (`th_*.py`) — standalone modules with a `HEURISTIC` constant and a `ThreatMaterializer` class. Used for heuristics requiring complex procedural logic.

Python takes precedence when both formats define the same `rule_id`.

| Rule | Pattern | Detection Signal |
|---|---|---|
| TH-001 | Internet-exposed module handling sensitive workflow data | `internet_exposed` + workflow with classified objects |
| TH-002 | Low-trust to high-value object dependency path | Low-trust domain → dependency chain → sensitive datastore |
| TH-003 | High-privilege module externally reachable | `privilege >= service` + `internet_exposed` or workflow path |
| TH-004 | AI-relevant module dependency and model service exposure | `ai_relevant` module/datastore in dependency path |
| TH-005 | Regulated object concentration in critical workflows | Multiple `regulated` objects + privileged modules in workflow |
| TH-006 | Trust boundary crossing with privileged dependency | `DEPENDS_ON` crossing `TrustBoundary` into privileged zone |

### Why 6 heuristics vs hundreds of techniques

Heuristics and techniques serve different roles:

- **Heuristics** are *graph pattern detectors* — they find structural conditions in the architecture model (modules, domains, trust boundaries, privilege levels, workflows, objects, dependencies).
- **Techniques** (ATT&CK/ATLAS) are *attack method classifications* — they describe *how* an attacker exploits a condition.

The relationship is many-to-many via the mapping engine. One heuristic can trigger multiple techniques, and the tactic-expansion layer broadens coverage further. But most ATT&CK techniques (~80%) describe runtime behaviors — phishing, memory corruption, credential dumping — that have no detectable precondition in an architecture-level graph.

### Why heuristics are statically defined

- **Determinism** — same model always produces the same threats (core design principle).
- **Domain judgment** — each heuristic encodes expert reasoning about which graph patterns indicate real risk.
- **Auditability** — every threat traces back to a specific rule ID, Cypher query, and rationale.
- **Graph schema coupling** — heuristics are Cypher queries against a specific node/relationship schema; they must match the model structure precisely.

Heuristic definitions can be authored in **TOML** (declarative, no Python required) or **Python** (procedural, for complex logic). Both formats are loaded at runtime — the system supports adding new rules without modifying existing code.

### Current detection surface

The canonical model exposes ~5 properties relevant to threat detection:

| Property | Location | Used by |
|---|---|---|
| `internet_exposed` | `Module` | TH-001, TH-003 |
| `ai_relevant` | `Module`, `DataStore`, `Object` | TH-004 |
| `classification` | `Object` | TH-001, TH-002 |
| `regulated` | `Object` | TH-005 |
| `trust_level` | `SecurityDomain` | TH-002, TH-006 |

The heuristic count is constrained by the model's expressiveness, not by implementation capacity. Expanding the heuristic set requires either richer patterns from the existing model or enriching the model schema.

---

## 2. Can Heuristics Be Derived from ATT&CK at Sync Time?

### Full auto-generation does not work

A heuristic is a *Cypher query* that detects a structural pattern. ATT&CK technique metadata contains tactics, platforms, data sources, and prose descriptions — but nothing that maps directly to a Cypher pattern like "find modules where `internet_exposed = true` AND a dependency path reaches a datastore containing `classification = 'secret'` objects." That graph-to-behavior bridge requires domain judgment, not extractable data.

### What does work: precondition-based clustering

A subset of techniques DO have structured preconditions that map to model properties:

| ATT&CK metadata | Model property | Example techniques |
|---|---|---|
| `x_mitre_platforms` contains "Network" | `Module.internet_exposed` | T1190, T1133 |
| Tactic = "Initial Access" | Module in low-trust domain + external dependency | T1190, T1078 |
| Tactic = "Lateral Movement" | Cross-domain dependency path | T1021, T1550 |
| Technique targets credentials | `Object.object_type == "credential"` | T1078, T1552 |
| Technique targets ML models | `Module.ai_relevant` or `DataStore.ai_relevant` | AML.T0016, AML.T0040 |

**Precondition clustering** at sync time could:

1. Parse technique metadata to extract architectural preconditions (platform, access level, target type)
2. Group techniques by precondition signature (e.g., all "requires network-exposed service" techniques cluster together)
3. Generate **candidate heuristic skeletons** — a precondition description + the list of techniques it would map to
4. A curated activation step decides which skeletons become real Cypher-backed heuristics

This flips the workflow: instead of writing a heuristic and then mapping it to techniques, you start from technique clusters and ask "do we have the graph signal to detect this precondition?"

```
sync time:
  ATT&CK techniques → extract preconditions → cluster → store in KB

design time (human):
  review clusters → write Cypher for detectable ones → activate as heuristics

runtime:
  activated heuristics → execute Cypher → auto-map to full technique cluster
```

The tactic-expansion layer already does half of this. Precondition clustering would make expansion smarter — instead of "all Initial Access techniques," it would be "all Initial Access techniques that require a network-exposed endpoint."

---

## 3. Framework-Driven Heuristic Expansion

Several established frameworks define threat patterns with structured architectural preconditions. These can systematically generate heuristics rather than relying on ad-hoc pattern authoring.

### 3.1 STRIDE-per-Element (Most Directly Applicable)

Microsoft's threat modeling methodology assigns threat categories to *element types* in a data flow diagram. This maps directly to the graph model:

| Element Type | Graph Equivalent | STRIDE Threats |
|---|---|---|
| Process | `Module` | S, T, R, I, D, E |
| Data Store | `DataStore` | T, I, D |
| Data Flow | `DEPENDS_ON` relationship | T, I, D |
| External Entity | `ExternalActor` | S, R |
| Trust Boundary Crossing | `TrustBoundary` + cross-domain `DEPENDS_ON` | All amplified |

Each combination is a heuristic candidate. The current 6 heuristics cover a few intersections. STRIDE-per-element would systematically generate ~20–30:

- **Spoofing**: external actor → module across trust boundary without auth-capable module in path
- **Tampering**: data flow to datastore crosses trust boundary, datastore contains regulated objects
- **Information Disclosure**: high-classification object accessible via dependency chain from low-trust domain
- **Denial of Service**: internet-exposed module with multiple downstream dependents (fan-out)
- **Elevation of Privilege**: dependency path from low-privilege module to high-privilege module

The key insight: STRIDE gives a *systematic enumeration* instead of ad-hoc pattern authoring. Every element × category combination either produces a detectable pattern or is explicitly marked "not detectable at architecture level."

### 3.2 CAPEC (Common Attack Pattern Enumeration and Classification)

CAPEC is more architectural than ATT&CK. Each entry includes structured fields:

- **Prerequisites** — conditions that must exist (e.g., "target relies on client-side validation")
- **Related Weaknesses** (CWEs)
- **Domains of Attack** — Software, Hardware, Social Engineering, Supply Chain
- **Abstraction Level** — Meta, Standard, Detailed

CAPEC entries at the "Meta" and "Standard" levels describe architectural conditions rather than implementation details:

| CAPEC | Pattern | Graph Signal |
|---|---|---|
| CAPEC-122 (Privilege Abuse) | Excessive privilege on accessible component | `Module.privilege >= service` + reachable from low-trust |
| CAPEC-216 (Communication Channel Manipulation) | Unprotected data flow across boundary | `DEPENDS_ON` crossing `TrustBoundary` |
| CAPEC-233 (Privilege Escalation) | Path from low to high privilege | `DEPENDS_ON*` path with increasing privilege levels |
| CAPEC-113 (Interface Manipulation) | Exposed API surface | `Module.internet_exposed` + sensitive data |

There are ~550 CAPEC entries. Filtering to Meta/Standard abstraction + Software domain + architectural prerequisites yields ~60–80 with graph-detectable preconditions.

### 3.3 NIST SP 800-53 Control Families (Inverse Approach)

Instead of "what attacks are possible?" ask "what controls are *missing*?" Each control implies an architectural property:

| Control | Architectural Precondition | Missing = Heuristic |
|---|---|---|
| AC-4 (Information Flow Enforcement) | Data flows cross trust boundaries | No enforcement module in path |
| SC-7 (Boundary Protection) | Trust boundary exists | No gateway/firewall module at boundary |
| IA-2 (Identification and Authentication) | External actor accesses internal module | No auth module in workflow path |
| SI-10 (Information Input Validation) | Internet-exposed module receives data | No validation layer before processing |

This flips the model: heuristics detect the *absence* of expected architectural controls rather than the presence of attack patterns. Requires enriching the model with control annotations or inferring them from module types.

### 3.4 Microsoft SDL Threat Modeling Patterns

The Microsoft SDL defines a pattern catalog with formal production rules — directly translatable to Cypher:

```
IF   data flow crosses trust boundary
AND  data flow carries sensitive data
AND  no encryption module in path
THEN Information Disclosure threat
```

```cypher
MATCH (src:Module)-[:DEPENDS_ON]->(dst:Module),
      (src)-[:IN_DOMAIN]->(d1:SecurityDomain),
      (dst)-[:IN_DOMAIN]->(d2:SecurityDomain),
      (tb:TrustBoundary)-[:CROSSES_FROM]->(d1),
      (tb)-[:CROSSES_TO]->(d2)
WHERE d1.trust_level <> d2.trust_level
RETURN src, dst, tb
```

### 3.5 OWASP Verification Standards (ASVS + MASVS)

**ASVS** (Application Security Verification Standard) defines ~280 verification requirements organized by architectural concern (authentication, session management, access control, cryptography). At the graph level, ~40–50 have structural preconditions:

- V1.2.1: Trust boundary enforcement between components
- V1.4.1: Access control enforcement at gateway
- V1.6.1: Cryptographic service isolation

**MASVS** (Mobile Application Security Verification Standard) is the mobile counterpart. While many of its requirements target implementation-level controls (certificate pinning, keychain usage), a subset maps to architectural preconditions detectable in the graph:

| MASVS Category | Architectural Signal | Graph Equivalent |
|---|---|---|
| MASVS-NETWORK | Unprotected data flow to/from mobile client | `DEPENDS_ON` crossing trust boundary to external module |
| MASVS-AUTH | Authentication bypass paths | Dependency path skipping auth-capable module |
| MASVS-STORAGE | Sensitive data on low-trust device | `Object.classification` in module within low-trust domain |
| MASVS-CRYPTO | Crypto service isolation | Missing encryption module in data flow path |

MASVS is most valuable in Phase 3 (model enrichment), where adding a `deployment_context` or `platform_type` property to modules unlocks mobile-specific heuristics. The ATT&CK `mobile` domain is already syncable (`attack_domains` is configurable), so technique mappings for mobile heuristics come through the existing mapping engine with no additional work.

---

## 4. Recommended Expansion Path

### Phase 1 — STRIDE-per-Element Enumeration

Adopt STRIDE-per-element as the systematic enumeration framework:

1. Enumerate every graph element type × STRIDE category combination
2. For each combination, determine if the current model has sufficient signal
3. Implement detectable combinations as new heuristics (TH-007+)
4. Map each to ATT&CK/ATLAS via the existing layered mapping engine

Expected yield: expand from 6 to ~25 heuristics with no model schema changes.

### Phase 2 — CAPEC Meta/Standard Gap Fill

Where STRIDE identifies a threat category but does not specify the pattern shape, use CAPEC Meta/Standard entries to provide the architectural precondition structure.

Expected yield: ~10 additional heuristics covering privilege escalation paths, communication channel patterns, and supply-chain dependency risks.

### Phase 3 — Model Schema Enrichment

Each new detection category reveals what the model is missing. Incrementally add properties to unlock the next tier of heuristics:

| Property | Location | Unlocks |
|---|---|---|
| `authentication_required` | `Module` or `DEPENDS_ON` | Spoofing detection, unauthenticated access paths |
| `encryption_in_transit` | `DEPENDS_ON` relationship | Information disclosure across boundaries |
| `input_validation` | `Module` | Injection and manipulation detection |
| `rate_limiting` | `Module` | DoS exposure detection |
| `logging_enabled` | `Module` | Repudiation detection |
| `api_endpoints` | `Module` (list) | Interface-specific attack surface |
| `data_flow_direction` | `DEPENDS_ON` relationship | Directional flow analysis |
| `deployment_context` | `Module` | Platform-aware technique filtering |

Each property addition enables a new cluster of STRIDE-per-element and CAPEC heuristics.

### Phase 4 — Control-Gap Detection (NIST 800-53)

Add control annotations to the model and implement absence-based heuristics. This shifts from "what attacks are possible?" to "what controls are missing?" — a complementary perspective that strengthens the analysis.

---

## 5. ATT&CK Integration Strategy

Expanded heuristics connect to ATT&CK/ATLAS through the existing layered mapping engine:

```
STRIDE-per-element heuristic
    → vector-based suggestion (Layer 0: candidate retrieval)
    → curated technique mappings (Layer 1: TOML rules)
    → tactic-based expansion (Layer 2: TechniqueIndex)
    → context filtering (Layer 3: model metadata)
```

**Layer 0 — Vector-based technique suggestion** (implemented) uses dense-vector similarity to discover candidate technique bindings for heuristics. At sync time (`threatforge sync --embed`), technique descriptions are encoded into 384-dimensional embeddings and stored in the knowledge base. The `SuggestionScorer` (`src/analysis/suggestion_scorer.py`) blends cosine similarity (60%) with tactic-overlap bonuses (25%) and framework-match bonuses (15%) to rank candidates. This is an offline advisory layer — candidates are surfaced via `threatforge suggest-mappings` for human review and promotion to curated mappings.

Precondition clustering at sync time would make Layer 2 smarter by grouping techniques by architectural precondition signature rather than by tactic alone.

---

## 6. Summary

| Approach | Heuristic Yield | Model Changes | Implementation Effort |
|---|---|---|---|
| STRIDE-per-element | ~20–25 | None | Medium |
| CAPEC Meta/Standard | ~10 additional | None | Medium |
| Model enrichment | ~15–20 per property | Schema extension | Large (per property) |
| OWASP ASVS + MASVS | ~10–15 (ASVS now, MASVS with enrichment) | `deployment_context` for MASVS | Medium–Large |
| NIST 800-53 control gaps | ~15–20 | Control annotations | Large |
| ATT&CK precondition clustering | Improves mapping quality | None | Medium |
| **Vector-based technique suggestion** | **Improves mapping discovery** | **None** | **Done** |

The bottleneck is the model, not the heuristics. STRIDE-per-element is the highest-value next step — it provides a structured audit of "which element × threat combinations can we detect?" and produces a clear gap analysis for subsequent model enrichment.

---

## 7. Config-Driven Heuristic Implementation

> Implemented: 2026-04-18

The heuristic engine now supports a **hybrid Python/TOML** approach. Each heuristic can be defined either as a Python module or as a TOML configuration file. Both are auto-discovered at import time and registered through the same `ThreatMaterializer` protocol.

### File layout

```
src/analysis/heuristics/
    __init__.py               # Discovery engine (Python + TOML)
    generic_materializer.py   # Config-driven materializer class
    th_001.py – th_006.py     # Python heuristic modules (existing)
    rules/                    # TOML-defined heuristics
        th_001.toml – th_006.toml
```

### TOML rule format

Each `.toml` file contains two required sections:

```toml
[heuristic]
rule_id = "TH-007"
name = "Short descriptive name"
description = """Detailed description of the threat pattern."""
graph_pattern = """Cypher-style pattern description"""
target_type = "module"             # module | workflow | object | datastore | system
severity_hint = "high"             # low | medium | high | critical
frameworks = ["ATTACK"]            # ATTACK | ATLAS
output_field_mapping = ["target_id <- module.id", "..."]

[materializer]
primary = "snapshot_key"           # Key into the graph snapshot dict
sort_by = ["field_a", "field_b"]   # Deterministic row ordering
skip_if_empty = "field_a"          # Skip rows where this field is empty
target_id_field = "field_a"        # Row field used as ThreatRecord.target_id
id_fields = ["field_a"]            # Fields combined for stable_id generation
rationale = "Human-readable rationale text."

[materializer.evidence]            # Evidence dict: key = output name, value = reference
some_field = "row.field_name"      # row.* resolves to the current row
agg_count = "$collect_name.unique_count"  # $name.attr resolves to collected/joined data

[materializer.affected]
workflows = "$collected.unique_values"   # String ref to collected data
objects = ["row.target_object"]          # List with mixed row/collected refs
```

### Optional materializer sections

**`[materializer.filter]`** — Skip rows where a field value is not in a whitelist:

```toml
[materializer.filter]
field = "relationship"
in = ["calls", "reads_writes", "writes"]
```

**`[materializer.collect.<name>]`** — Pre-aggregate data from a secondary snapshot key:

```toml
[materializer.collect.sensitive_data]
source = "sensitive_workflows"     # Snapshot key to aggregate
unique_field = "workflow_id"       # Deduplicate values from this field
flatten_field = "sensitive_objects" # Flatten lists from this field
```

Results are referenced as `$sensitive_data.unique_values`, `$sensitive_data.flattened_values`, or `$sensitive_data.unique_count`.

**`[materializer.join.<name>]`** — Per-row join against a secondary snapshot key:

```toml
[materializer.join.regulated]
source = "regulated_data"          # Snapshot key to join against
match_value_field = "workflow_id"  # Row field providing the match value
match_in = "workflows"             # Field in source rows containing match candidates
collect = "regulated_object"       # Field to collect from matching source rows
```

Results are referenced as `$regulated.matched_keys`.

### GenericMaterializer

The `GenericMaterializer` class (in `generic_materializer.py`) interprets the `[materializer]` config at runtime. It satisfies the `ThreatMaterializer` protocol with the same `rule_id` + `materialize()` signature as hand-coded Python materializers. The class handles:

- **Primary iteration** — sorted traversal of the snapshot key specified by `primary`
- **Skip/filter** — row-level exclusion via `skip_if_empty` and `filter.in`
- **Cross-reference collection** — pre-aggregation of secondary snapshot data via `collect`
- **Per-row joins** — matching against secondary data via `join`
- **Evidence resolution** — `row.*` references, `$name.attr` references to collected/joined data
- **Affected list resolution** — mixed `row.*` and `$name.*` references for workflows/objects

### Discovery precedence

The discovery engine in `heuristics/__init__.py` loads TOML rules first, then Python modules. When both define the same `rule_id`, the **Python module takes precedence**. This allows:

1. Existing Python heuristics to continue working unchanged
2. TOML rules to serve as the default for simple/standard patterns
3. A Python module to override a TOML rule when complex logic is needed

### Parity verification

All 6 existing heuristics have both Python and TOML definitions. The test suite (`test_generic_materializer.py`) verifies that TOML-driven materializers produce **identical output** to their Python counterparts for the same snapshot data. This includes matching on `threat_id`, `target_id`, `evidence`, `affected_workflows`, `affected_objects`, and all other `ThreatRecord` fields.

### Adding a new TOML-only heuristic

1. Create `src/analysis/heuristics/rules/th_007.toml` with `[heuristic]` and `[materializer]` sections
2. Add technique mappings in `data/threat_intel/mapping_rules.toml`
3. No Python code changes required — the heuristic and materializer are discovered automatically

---

## 8. Phase 2 — CAPEC Meta/Standard Gap Fill

> Implemented: 2026-04-19

Phase 2 uses CAPEC Meta/Standard entries to fill gaps where STRIDE identifies a threat category but does not specify the architectural pattern shape. This adds 10 heuristics (TH-015 through TH-024) covering three focus areas: **privilege escalation paths**, **communication channel patterns**, and **supply-chain dependency risks**.

### New heuristics

| Rule | CAPEC | Name | Target | Severity | Detection Signal |
|---|---|---|---|---|---|
| TH-015 | CAPEC-233 | Transitive privilege escalation through dependency chain | module | critical | A→B→C with increasing privilege at each hop |
| TH-016 | CAPEC-69 | External actor workflow path to privileged module | module | high | Actor→Workflow→Module with privilege ≥ service |
| TH-017 | CAPEC-122 | Low-trust module writes to higher-trust datastore | datastore | high | Low-trust Module →{writes}→ DataStore in higher-trust domain |
| TH-018 | CAPEC-560 | Credential object exposed in low-trust workflow | object | critical | Credential object in workflow with low-trust module |
| TH-019 | CAPEC-176 | High fan-in dependency target | module | medium | Module/DataStore with ≥3 incoming dependencies |
| TH-020 | CAPEC-216 | Workflow spanning disparate trust levels | workflow | high | Low + high trust modules in same workflow |
| TH-021 | CAPEC-113 | External actor accessing workflow with regulated data | workflow | high | Actor in workflow with regulated objects |
| TH-022 | CAPEC-438 | AI datastore accessible from low-trust module | datastore | high | Low-trust module → AI-relevant DataStore |
| TH-023 | CAPEC-439 | Dependency chain crossing three distinct security domains | module | medium | A(D1)→B(D2)→C(D3) through 3 distinct domains |
| TH-024 | CAPEC-212 | Internet-exposed module with transitive sensitive datastore access | module | high | Exposed module→chain→sensitive DataStore |

### CAPEC coverage mapping

Each heuristic maps a CAPEC architectural precondition to a detectable graph pattern:

- **Privilege escalation paths** (CAPEC-233, CAPEC-69, CAPEC-122): TH-015 extends TH-011's direct privilege gap to multi-hop chains. TH-016 traces the full actor-to-privilege path. TH-017 detects cross-trust write access.
- **Communication channel patterns** (CAPEC-216, CAPEC-113, CAPEC-560): TH-020 detects workflows bridging the widest trust gap. TH-021 catches external access to regulated data. TH-018 catches credential exposure in low-trust workflows.
- **Supply-chain dependency risks** (CAPEC-438, CAPEC-439, CAPEC-176, CAPEC-212): TH-022 protects AI datastores from untrusted access. TH-023 detects multi-domain traversal. TH-019 identifies high-value manipulation targets. TH-024 traces deep exposure paths from internet-facing modules.

### Implementation details

All 10 heuristics are TOML-only — no Python modules required. Each adds:

1. A **Cypher query** in `graph_queries.py` (10 new methods under the `CAPEC expansion queries` section)
2. A **snapshot key** in `threat_outputs._build_snapshot()` (10 new entries)
3. A **TOML rule file** in `src/analysis/heuristics/rules/` (th_015.toml – th_024.toml)
4. **Curated technique mappings** in `data/threat_intel/mapping_rules.toml` (20 new entries, 2 per heuristic)

### Technique mapping summary

| Rule | Techniques | Frameworks |
|---|---|---|
| TH-015 | T1068, T1548 | ATT&CK |
| TH-016 | T1078, T1068 | ATT&CK |
| TH-017 | T1565, T1485 | ATT&CK |
| TH-018 | T1552, T1078 | ATT&CK |
| TH-019 | T1195, T1574 | ATT&CK |
| TH-020 | T1557, T1021 | ATT&CK |
| TH-021 | T1530, T1020 | ATT&CK |
| TH-022 | AML.T0016, AML.T0040 | ATLAS |
| TH-023 | T1570, T1090 | ATT&CK |
| TH-024 | T1005, T1190 | ATT&CK |

### Test coverage

The test suite (`test_generic_materializer.py`) adds 29 new tests:

- **10 TOML parsing tests** — verify each rule parses with correct rule_id, name, target_type, severity, and frameworks
- **10 materializer output tests** — verify each rule produces the expected number of threats from synthetic snapshot data
- **5 field-level tests** — verify evidence, affected_workflows, and affected_objects for representative heuristics (TH-015, TH-016, TH-018, TH-020, TH-021)
- **1 empty snapshot test** — verify all 10 heuristics produce 0 threats from empty snapshot
- **3 discovery integration tests** — verify all 10 rules are discovered, registered, and the total count reaches 24

Full test suite result: **188 passed**, 3 pre-existing failures (unchanged from Phase 1 baseline).

### Heuristic count progression

| Phase | Heuristics | Total |
|---|---|---|
| Phase 0 (original) | TH-001 – TH-006 | 6 |
| Phase 1 (STRIDE) | TH-007 – TH-014 | 14 |
| Phase 2 (CAPEC) | TH-015 – TH-024 | 24 |
| Phase 3 (Enrichment) | TH-025 – TH-034 | **34** |

---

## 9. Phase 3 — Model Schema Enrichment

> Implemented: 2026-04-20

Phase 3 adds 8 new properties to the canonical model schema and 10 heuristics (TH-025 through TH-034) that detect **control absences** — missing authentication, encryption, input validation, rate limiting, and logging. This shifts from "what attacks are possible?" toward "what controls are missing?" — the perspective that Phase 4 (NIST 800-53) will build on.

### New schema properties

All properties are optional with backward-compatible defaults. Existing TOML models continue to work unchanged.

**Module properties:**

| Property | Type | Default | Unlocks |
|---|---|---|---|
| `authentication_required` | `bool` | `False` | Spoofing detection, unauthenticated access paths |
| `input_validation` | `bool` | `False` | Injection and manipulation detection |
| `rate_limiting` | `bool` | `False` | DoS exposure detection |
| `logging_enabled` | `bool` | `False` | Repudiation detection |
| `api_endpoints` | `list[str]` | `[]` | Interface-specific attack surface |
| `deployment_context` | `str \| None` | `None` | Platform-aware technique filtering |

**Dependency properties:**

| Property | Type | Default | Unlocks |
|---|---|---|---|
| `encryption_in_transit` | `bool` | `False` | Information disclosure across boundaries |
| `data_flow_direction` | `str \| None` | `None` | Directional flow analysis |

### New heuristics

| Rule | Property | Name | Target | Severity | Detection Signal |
|---|---|---|---|---|---|
| TH-025 | `authentication_required` | External actor reaches unauthenticated module | module | high | Actor→Workflow→Module without auth |
| TH-026 | `encryption_in_transit` | Unencrypted flow crossing trust boundary | module | high | Unencrypted dep across boundary |
| TH-027 | `input_validation` | Internet-exposed module without input validation | module | high | Exposed + no validation |
| TH-028 | `rate_limiting` | Internet-exposed module without rate limiting | module | medium | Exposed + no rate limit + downstream |
| TH-029 | `logging_enabled` | Module in critical workflow without logging | module | medium | Unlogged in critical workflow |
| TH-030 | `encryption_in_transit` | Unencrypted dep to classified datastore | datastore | high | Unencrypted + classified data |
| TH-031 | `data_flow_direction` | Bidirectional flow across trust boundary | module | medium | Bidirectional + boundary crossing |
| TH-032 | `api_endpoints` | API endpoints accessible across boundary | module | high | Endpoints in boundary-target domain |
| TH-033 | `authentication_required` | Unauthenticated chain to privileged module | module | critical | No auth on path to privilege ≥ 2 |
| TH-034 | `deployment_context` | Mobile/edge module handling regulated data | module | high | Mobile/edge + regulated objects |

### Implementation details

Changes span the full stack:

1. **Schema** (`src/models/schema/canonical_model.py`): 6 new fields on `Module`, 2 on `Dependency`
2. **Graph loader** (`src/graph/graph_loader.py`): `_merge_modules` and `_merge_dependencies` SET the new properties
3. **Example model** (`examples/fintech_ai_platform.toml`): All modules and dependencies annotated with new properties
4. **Cypher queries** (`src/graph/graph_queries.py`): 10 new methods under `Schema enrichment queries (Phase 3)`
5. **Snapshot builder** (`src/analysis/threat_outputs.py`): 10 new snapshot keys
6. **TOML rules** (`src/analysis/heuristics/rules/th_025.toml` – `th_034.toml`): 10 new heuristic definitions
7. **Technique mappings** (`data/threat_intel/mapping_rules.toml`): 20 new curated entries

### Technique mapping summary

| Rule | Techniques | Frameworks |
|---|---|---|
| TH-025 | T1078, T1134 | ATT&CK |
| TH-026 | T1040, T1557 | ATT&CK |
| TH-027 | T1190, T1059 | ATT&CK |
| TH-028 | T1499, T1498 | ATT&CK |
| TH-029 | T1070, T1562 | ATT&CK |
| TH-030 | T1040, T1005 | ATT&CK |
| TH-031 | T1557, T1565 | ATT&CK |
| TH-032 | T1190, T1106 | ATT&CK |
| TH-033 | T1068, T1548 | ATT&CK |
| TH-034 | T1005, T1414 | ATT&CK |

### Test coverage

**Schema tests** (`test_schema.py`): 4 new tests verifying property parsing and defaults for both Module and Dependency enrichment fields.

**Graph loader tests** (`test_graph_loader.py`): 3 new tests verifying Cypher SET clauses include the new properties and batch data carries correct values.

**Heuristic tests** (`test_generic_materializer.py`): 29 new tests:
- 10 TOML parsing tests
- 10 materializer output tests
- 5 field-level tests (TH-025, TH-027, TH-029, TH-033, TH-034)
- 1 empty snapshot test
- 3 discovery integration tests (including total count = 34)

Full test suite result: **224 passed**, 3 pre-existing failures (unchanged).
