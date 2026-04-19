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
