# Threat Forge AI — Full Project Kit

## Project Identity

**Working title:** Threat Forge AI  
**Category:** AI-assisted security architecture / threat modeling / agentic analysis  
**Primary goal:** Build a portfolio-grade MVP that can evolve into a real product.

---

## 1. One-Page Architecture

### 1.1 Product vision
A model-driven security analysis platform that converts heterogeneous technical inputs into a canonical system model, loads that model into a security graph, generates ATT&CK- and ATLAS-aligned threats, computes explainable risk prioritization, and exposes the results through agentic LLM workflows.

### 1.2 Core design principles
- Canonical model first
- Graph-native reasoning
- Deterministic analysis where possible
- LLMs as analysis and interaction layer, not source of truth
- Versioned artifacts for reproducibility
- Modular architecture that can grow from MVP to product

### 1.3 End-to-end flow
```text
Inputs
(specs, informal descriptions, SBOM, codebase signals)
        ↓
Intake + normalization
        ↓
Canonical TOML system model
        ↓
Graph loader
        ↓
Security graph
        ↓
Threat engine + risk engine
        ↓
Agent query interface
        ↓
Later: red-team plans + mitigation strategies
```

### 1.4 System modules

#### A. Intake module
Purpose:
- collect evidence from multiple sources
- normalize extracted facts
- propose updates to the canonical model

Inputs:
- specifications
- architecture notes
- SBOM
- codebase analysis
- informal system descriptions

Outputs:
- evidence objects
- validated TOML model changes

#### B. Canonical model module
Purpose:
- define the system of interest in a stable machine-readable format
- serve as the source of truth for downstream analysis

Representation:
- TOML files in Git
- schema validated with Pydantic

#### C. Graph module
Purpose:
- transform the TOML system model into a graph for traversal, querying, and attack-path analysis

Suggested store:
- Neo4j

#### D. Threat modeling engine
Purpose:
- inspect system relationships
- generate ATT&CK and ATLAS aligned threat candidates
- attach rationale and supporting context

#### E. Risk modeling engine
Purpose:
- prioritize generated threats using an explainable scoring framework
- support analyst triage and future mitigation planning

#### F. Agent query layer
Purpose:
- let users interrogate the system in natural language
- orchestrate graph queries, RAG retrieval, and reasoning tools

Frameworks:
- LangGraph
- LangChain tools
- LangSmith for tracing

#### G. RAG knowledge layer
Purpose:
- provide structured external security knowledge to the agents

Knowledge sources:
- MITRE ATT&CK
- MITRE ATLAS
- CWE
- OWASP
- NIST guidance

#### H. Phase 2 modules
- red team planning
- mitigation strategy generation

### 1.5 Recommended MVP architecture
```text
Manual TOML model
    ↓
Schema validator
    ↓
Neo4j graph loader
    ↓
Threat generation rules
    ↓
Risk scoring
    ↓
LangGraph query agent
    ↓
Streamlit analyst UI
```

### 1.6 What makes the MVP compelling
- strong security architecture orientation
- visible use of agent frameworks
- explainable model-driven reasoning
- graph-native analysis
- extensible product story

---

## 2. Phased Backlog

## Phase 0 — Framing and design
**Goal:** turn the idea into an executable system design.

### Deliverables
- project brief
- architecture overview
- canonical schema draft
- demo scenario definition
- technology choices

### Tasks
- define the target user and usage scenario
- choose the demo domain
- define MVP boundaries
- identify core entities and relationships
- choose scoring philosophy for risk
- define what “good output” looks like for threats and risks

### Exit criteria
- architecture is stable enough to implement
- one demo system is selected
- TOML schema first draft exists

---

## Phase 1 — Canonical model and example system
**Goal:** establish the system model as the backbone of the platform.

### Deliverables
- TOML schema draft
- Pydantic schema validator
- example model file
- example domain documentation

### Tasks
- define TOML sections and field naming conventions
- create Pydantic models for all entities
- implement validation and loading logic
- create one realistic example system
- add versioned examples in Git

### Exit criteria
- a valid TOML model can be loaded and validated
- the example model contains enough richness for threat analysis

---

## Phase 2 — Graph foundation
**Goal:** transform the canonical model into an analyzable graph.

### Deliverables
- graph schema
- Neo4j loader
- query library
- attack-path exploration helpers

### Tasks
- define node labels and relationship types
- implement TOML → graph loading
- create graph constraints and indexes
- create 8–12 useful Cypher queries
- validate graph correctness against the example model

### Exit criteria
- the example system is queryable through the graph
- core relationship queries work end-to-end

---

## Phase 3 — Threat generation engine
**Goal:** generate meaningful ATT&CK- and ATLAS-aligned threats.

### Deliverables
- threat generation module
- framework mapping module
- structured threat outputs

### Tasks
- define threat generation heuristics
- map graph patterns to ATT&CK techniques
- add ATLAS coverage for AI-specific modules
- generate threat objects with rationale
- store outputs in a structured format

### Exit criteria
- the system produces nontrivial threats for the example domain
- each threat has a target, technique mapping, and rationale

---

## Phase 4 — Risk prioritization engine
**Goal:** convert threats into prioritized, explainable risks.

### Deliverables
- scoring model
- risk generation module
- analyst-readable explanations

### Tasks
- define risk factors
- implement weighted risk scoring
- normalize output scale
- produce priority tiers
- create explanation strings for each score

### Exit criteria
- threats are converted into prioritized risks
- risk outputs are consistent and explainable

---

## Phase 5 — Agent orchestration and RAG
**Goal:** expose the analysis through agent workflows.

### Deliverables
- LangGraph workflow
- tool interfaces
- RAG retriever
- LangSmith traces

### Tasks
- define graph query tools
- define threat and risk lookup tools
- ingest MITRE/OWASP/CWE materials into a retriever
- add a query agent that routes questions to the right tools
- instrument with LangSmith

### Exit criteria
- users can ask questions in natural language
- the agent can combine graph and retrieval evidence
- traces are visible in LangSmith

---

## Phase 6 — MVP analyst interface
**Goal:** package the system into a usable demo.

### Deliverables
- Streamlit UI
- workflow buttons / commands
- model upload or example selection
- analysis results views

### Tasks
- create simple analyst screens
- show system model summary
- show threats and risks
- show reasoning metadata and source techniques
- add “rebuild analysis” workflow

### Exit criteria
- someone can run the MVP locally and understand the workflow
- the demo is portfolio-ready

---

## Phase 7 — Portfolio polish
**Goal:** turn the MVP into a demonstrable professional artifact.

### Deliverables
- polished README
- architecture diagrams
- walkthrough case study
- screenshots
- demo script
- design rationale write-up

### Tasks
- write the product narrative
- explain architectural trade-offs
- document the demo scenario
- add screenshots and sample outputs
- prepare a concise demo video outline

### Exit criteria
- project looks coherent and professionally framed
- the repo tells a strong AI + security story

---

## Phase 8 — Phase 2 extensions
**Goal:** expand toward a more product-like security analysis platform.

### Candidate features
- red-team plan generation
- mitigation recommendations
- ingestion automation for SBOM and code
- model diffing and recomputation
- multi-project support
- policy packs by domain
- graph attack-path ranking
- control coverage analysis

---

## 3. Repo Skeleton

```text
threat-forge-ai/
├── README.md
├── pyproject.toml
├── LICENSE
├── .env.example
├── .gitignore
├── data/
│   └── threat_intel/
│       ├── mapping_rules.toml          # Curated rule→technique bindings
│       ├── mapping_config.toml         # Expansion config (tactic-based, off by default)
│       └── threatforge_kb.db           # SQLite knowledge-base (generated by sync)
├── docs/
│   ├── architecture.md
│   ├── demo_script.md
│   ├── design_attack_atlas_ingestion.md
│   ├── domain_model.md
│   ├── graph_schema.md
│   ├── project_kit.md
│   ├── risk_methodology.md
│   ├── threat_methodology.md
│   ├── walkthrough.md
│   └── diagrams/                       # Mermaid sources (.mmd) exported to SVG
├── examples/
│   └── fintech_ai_platform.toml
├── models/
│   └── outputs/
│       ├── threats/
│       ├── risks/
│       └── traces/
├── src/
│   ├── models/
│   │   └── schema/
│   │       ├── canonical_model.py
│   │       ├── threat_model.py
│   │       └── risk_model.py
│   ├── graph/
│   │   ├── neo4j_client.py
│   │   ├── graph_loader.py
│   │   ├── graph_queries.py
│   │   └── cypher/
│   │       ├── constraints.cypher
│   │       ├── indexes.cypher
│   │       └── sample_queries.cypher
│   ├── knowledge/
│   │   ├── models.py                   # Tactic, Technique, Mitigation dataclasses
│   │   ├── store.py                    # SQLite persistence layer
│   │   ├── index.py                    # In-memory TechniqueIndex singleton
│   │   ├── sync_attack.py              # ATT&CK STIX 2.1 parser + fetcher
│   │   ├── sync_atlas.py               # ATLAS YAML parser + fetcher
│   │   └── sync.py                     # Orchestrates full sync across domains
│   ├── analysis/
│   │   ├── threat_generation.py
│   │   ├── technique_mapping.py        # Layered mapping engine (curated + expansion)
│   │   ├── risk_scoring.py
│   │   └── threat_outputs.py
│   ├── agents/
│   │   ├── state.py
│   │   ├── tools.py
│   │   ├── workflow.py
│   │   └── observability.py
│   ├── ui/
│   │   ├── app.py
│   │   ├── actions.py
│   │   ├── data_access.py
│   │   └── pages/
│   │       ├── model_overview.py
│   │       ├── threats.py
│   │       ├── risks.py
│   │       └── chat.py
│   └── cli/
│       └── main.py                     # Unified CLI: validate, load-graph, generate-threats,
│                                       #   score-risks, ui, sync
└── tests/                              # 82 tests across 16 modules
```

---

## 4. TOML Schema Draft

## 4.1 Design goals
The TOML schema should:
- be readable by humans
- be easy to validate
- be versionable in Git
- support graph loading
- support incremental growth

## 4.2 Top-level sections
```toml
[meta]
[system]
[[security_domains]]
[[privilege_levels]]
[[modules]]
[[objects]]
[[datastores]]
[[external_actors]]
[[workflows]]
[[trust_boundaries]]
[[dependencies]]
```

## 4.3 Example schema draft
```toml
[meta]
schema_version = "0.1"
model_id = "fintech-ai-demo"
last_updated = "2026-03-15"
author = "Michel Kinasz"

[system]
name = "Fintech AI Payment Platform"
description = "A mobile payment platform with AI-assisted fraud analysis"
criticality = "high"
industry = "financial-services"

[[security_domains]]
id = "client"
name = "Client Domain"
trust_level = "low"

[[security_domains]]
id = "edge"
name = "Edge/API Domain"
trust_level = "medium"

[[security_domains]]
id = "backend"
name = "Backend Services"
trust_level = "high"

[[security_domains]]
id = "ml"
name = "ML Domain"
trust_level = "medium"

[[privilege_levels]]
id = "public"
level = 0
description = "Unauthenticated or public access"

[[privilege_levels]]
id = "user"
level = 1
description = "Authenticated end-user privileges"

[[privilege_levels]]
id = "service"
level = 2
description = "Backend service privileges"

[[privilege_levels]]
id = "admin"
level = 3
description = "Administrative privileges"

[[modules]]
id = "mobile_app"
name = "Mobile App"
module_type = "client_application"
domain = "client"
privilege = "user"
internet_exposed = true
processes_sensitive_data = true
description = "Customer mobile application"

[[modules]]
id = "api_gateway"
name = "API Gateway"
module_type = "gateway"
domain = "edge"
privilege = "service"
internet_exposed = true
processes_sensitive_data = true

[[modules]]
id = "auth_service"
name = "Auth Service"
module_type = "identity_service"
domain = "backend"
privilege = "service"
internet_exposed = false
processes_sensitive_data = true

[[modules]]
id = "payment_service"
name = "Payment Service"
module_type = "transaction_service"
domain = "backend"
privilege = "service"
internet_exposed = false
processes_sensitive_data = true

[[modules]]
id = "fraud_model_service"
name = "Fraud Model Service"
module_type = "ml_service"
domain = "ml"
privilege = "service"
internet_exposed = false
processes_sensitive_data = true
ai_relevant = true

[[objects]]
id = "user_credentials"
name = "User Credentials"
object_type = "credential"
classification = "secret"
regulated = true

[[objects]]
id = "payment_instruction"
name = "Payment Instruction"
object_type = "transaction_data"
classification = "confidential"
regulated = true

[[objects]]
id = "fraud_features"
name = "Fraud Features"
object_type = "feature_vector"
classification = "confidential"
regulated = true
ai_relevant = true

[[datastores]]
id = "txn_db"
name = "Transaction Database"
store_type = "relational_database"
domain = "backend"
contains = ["payment_instruction"]

[[datastores]]
id = "feature_store"
name = "Feature Store"
store_type = "feature_store"
domain = "ml"
contains = ["fraud_features"]
ai_relevant = true

[[external_actors]]
id = "customer"
name = "Customer"
actor_type = "end_user"

[[external_actors]]
id = "attacker"
name = "External Attacker"
actor_type = "threat_actor"

[[workflows]]
id = "user_login"
name = "User Login"
description = "Customer authenticates through mobile app"
steps = [
  "customer -> mobile_app",
  "mobile_app -> api_gateway",
  "api_gateway -> auth_service"
]
modules = ["mobile_app", "api_gateway", "auth_service"]
objects = ["user_credentials"]

[[workflows]]
id = "payment_execution"
name = "Payment Execution"
description = "Customer initiates payment and fraud checks are performed"
steps = [
  "customer -> mobile_app",
  "mobile_app -> api_gateway",
  "api_gateway -> payment_service",
  "payment_service -> fraud_model_service",
  "payment_service -> txn_db",
  "fraud_model_service -> feature_store"
]
modules = ["mobile_app", "api_gateway", "payment_service", "fraud_model_service"]
objects = ["payment_instruction", "fraud_features"]

[[trust_boundaries]]
id = "internet_boundary"
name = "Internet Boundary"
from_domain = "client"
to_domain = "edge"

[[trust_boundaries]]
id = "backend_ml_boundary"
name = "Backend to ML Boundary"
from_domain = "backend"
to_domain = "ml"

[[dependencies]]
source = "mobile_app"
target = "api_gateway"
relationship = "calls"

[[dependencies]]
source = "api_gateway"
target = "auth_service"
relationship = "calls"

[[dependencies]]
source = "api_gateway"
target = "payment_service"
relationship = "calls"

[[dependencies]]
source = "payment_service"
target = "fraud_model_service"
relationship = "calls"

[[dependencies]]
source = "payment_service"
target = "txn_db"
relationship = "writes"

[[dependencies]]
source = "fraud_model_service"
target = "feature_store"
relationship = "reads_writes"
```

## 4.4 Suggested future schema extensions
- identities and roles
- secrets and key material
- deployment environments
- APIs and endpoints
- control coverage
- known assumptions
- evidence provenance
- model version diffs

---

## 5. MVP Implementation Plan

## 5.1 MVP definition
A local-first portfolio MVP that:
- loads a manually created TOML system model
- validates it with Pydantic
- loads it into Neo4j
- generates ATT&CK/ATLAS-aligned threats using rules plus LLM assistance
- computes explainable risk scores
- answers analyst questions through a LangGraph-based query agent
- shows execution traces in LangSmith

## 5.2 Strict MVP boundaries
### In scope
- one demo domain
- one canonical model schema
- manual TOML creation
- graph loading
- deterministic threat heuristics
- simple explainable risk scoring
- one query agent
- Streamlit UI

### Out of scope
- automated code ingestion at full scale
- production auth and tenancy
- complex collaboration features
- continuous synchronization from live systems
- full enterprise deployment

## 5.3 Recommended demo domain
**AI-enabled fintech payment platform**

Why:
- fits strong security architecture experience
- supports classic ATT&CK techniques
- supports AI-relevant ATLAS techniques
- creates a compelling narrative for portfolio use

## 5.4 Six-week build plan

### Week 1 — Schema and example model
**Goal:** build the system backbone.

Tasks:
- define schema entities and fields
- implement Pydantic validation
- create one realistic TOML file
- document entity semantics

Outputs:
- `canonical_model.py`
- `fintech_ai_platform.toml`
- validation script

### Week 2 — Graph loader and queries
**Goal:** make the model analyzable.

Tasks:
- define Neo4j node and edge mappings
- implement loader
- create constraints and indexes
- write 8–12 Cypher queries

Outputs:
- graph loader
- graph schema doc
- sample graph queries

### Week 3 — Threat generation
**Goal:** create the first useful security outputs.

Tasks:
- define heuristic rules
- map graph patterns to ATT&CK / ATLAS
- output structured threats
- attach rationale strings

Outputs:
- `threat_generation.py`
- structured threats JSON or TOML

### Week 4 — Risk scoring
**Goal:** add prioritization.

Tasks:
- define scoring factors
- implement weighted score formula
- create priority bands
- generate explanations

Outputs:
- `risk_scoring.py`
- risk outputs
- methodology note

### Week 5 — LangGraph agent + RAG
**Goal:** expose the analysis interactively.

Tasks:
- create graph query tools
- create threat/risk lookup tools
- add a retriever over selected security corpus
- implement query routing in LangGraph
- enable LangSmith tracing

Outputs:
- `query_agent.py`
- `tools.py`
- traces in LangSmith

### Week 6 — UI + portfolio polish
**Goal:** make the MVP demoable.

Tasks:
- create Streamlit screens
- show model summary, threats, and risks
- add rebuild analysis actions
- refine README and architecture docs
- prepare screenshots and sample prompts

Outputs:
- working Streamlit demo
- polished repo
- demo narrative

## 5.5 Minimum useful UI
### Screen 1 — Model overview
- list modules
- list domains
- list workflows
- show trust boundaries

### Screen 2 — Threats
- show generated threats
- show ATT&CK / ATLAS mapping
- show rationale and affected components

### Screen 3 — Risks
- show ranked risks
- show scores and drivers
- show filters by severity or module

### Screen 4 — Analyst chat
- ask questions about threats, paths, risks, and modules
- show tool-backed answer with reasoning metadata

## 5.6 Suggested risk model for MVP
Use a weighted score across:
- likelihood
- impact
- exposure
- privilege sensitivity
- data criticality
- exploitability

Example normalized formula:
```text
risk_score =
  0.25 * likelihood +
  0.20 * impact +
  0.15 * exposure +
  0.15 * privilege_sensitivity +
  0.15 * data_criticality +
  0.10 * exploitability
```

Priority bands:
- `critical`: 0.85–1.00
- `high`: 0.65–0.84
- `medium`: 0.40–0.64
- `low`: below 0.40

## 5.7 Suggested first graph queries
- Which modules are internet exposed?
- Which high-value objects cross trust boundaries?
- Which workflows involve sensitive data?
- Which modules have high privilege and external reachability?
- Which modules depend on AI-relevant services?
- Which risks target the most critical workflow?
- Which threats affect regulated data?
- What attack paths connect low-trust domains to high-value assets?

## 5.8 Suggested initial threat heuristics
Examples:
- internet-exposed component + sensitive data → credential access / initial access techniques
- boundary crossing + privileged backend dependency → lateral movement / privilege misuse candidates
- AI-relevant module + feature store or model inputs → ATLAS data poisoning / model evasion / extraction candidates
- secrets or credentials in client or mobile zone → credential access candidates

## 5.9 What to emphasize in the final README
- this is a model-driven security analysis platform
- the TOML model is the source of truth
- the graph is used for relationship analysis and attack-path reasoning
- ATT&CK and ATLAS are used as threat knowledge frameworks
- LangGraph orchestrates query and analysis workflows
- LangSmith provides observability
- the MVP is intentionally narrow but architecturally extensible

## 5.10 Stretch goals after MVP
- ingest Syft SBOM output
- derive module relationships from code structure
- add mitigation recommendations
- generate red-team test plans
- add graph diffing on model updates
- add policy/control coverage mapping

---

## 6. Recommended Working Narrative

### Elevator pitch
Threat Forge AI is a graph-native, model-driven threat modeling platform that converts system architecture into a canonical security model, maps threats using ATT&CK and ATLAS, prioritizes them with an explainable risk engine, and exposes the results through agentic LLM workflows.

### Why this is portfolio-strong
It demonstrates:
- AI system orchestration
- security architecture reasoning
- graph-based modeling
- RAG design
- observable agent workflows
- extensible product thinking

---

## 7. Immediate Next Actions

### Today
- choose the demo domain name
- finalize the project name
- freeze MVP scope
- create the repo

### This week
- write schema draft v0.1
- implement validation
- produce example TOML
- sketch the graph mapping

### After that
- build graph loader
- write threat rules
- add risk engine
- wrap with LangGraph

---

# 8. Repo-Ready Starter Pack

## 8.1 `README.md`

```md
# Threat Forge AI

Threat Forge AI is a graph-native, model-driven threat modeling platform that converts system architecture into a canonical security model, maps threats using MITRE ATT&CK and MITRE ATLAS, prioritizes them with an explainable risk engine, and exposes the results through agentic LLM workflows.

## Why this project exists
This project is designed as both:
- a portfolio-grade MVP demonstrating AI + security architecture skills
- a foundation for a future product in AI-assisted threat modeling

The architectural thesis is simple:
- use a canonical system model as the source of truth
- load that model into a graph for relationship analysis
- generate threats and risks from structure, not from vague prompting
- use LLMs as reasoning and interaction layers over deterministic security artifacts

## MVP scope
The MVP supports:
- manual creation of a canonical TOML system model
- schema validation with Pydantic
- loading the model into Neo4j
- ATT&CK- and ATLAS-aligned threat generation
- explainable risk scoring
- LangGraph-based analyst query workflows
- LangSmith observability
- Streamlit demo UI

The MVP intentionally excludes:
- full production deployment
- large-scale automated code ingestion
- enterprise authentication and multi-tenancy
- live synchronization with external systems

## Core architecture
```text
Inputs
(specs, notes, SBOM, code signals)
        ↓
Intake + normalization
        ↓
Canonical TOML model
        ↓
Graph loader
        ↓
Neo4j security graph
        ↓
Threat engine + risk engine
        ↓
LangGraph query interface
        ↓
Streamlit analyst UI
```

## Repository structure
```text
threat-forge-ai/
├── examples/
├── docs/
├── src/
│   ├── models/
│   ├── ingestion/
│   ├── graph/
│   ├── knowledge/
│   ├── analysis/
│   ├── agents/
│   ├── app/
│   └── cli/
├── tests/
└── notebooks/
```

## Demo scenario
The initial demo system is an **AI-enabled fintech payment platform** with:
- mobile app
- API gateway
- auth service
- payment service
- fraud model service
- transaction database
- feature store

This scenario was chosen because it supports both:
- classic enterprise/security threats
- AI/ML-relevant ATLAS threats

## Technology choices
- Python
- Pydantic
- TOML
- Neo4j
- LangGraph
- LangChain tools
- LangSmith
- Streamlit
- optional vector store for RAG

## Development roadmap
### Phase 1
- define canonical schema
- validate example system model
- document graph schema

### Phase 2
- load system model into Neo4j
- implement graph queries
- support attack-path exploration

### Phase 3
- generate ATT&CK and ATLAS threats
- create structured threat outputs

### Phase 4
- implement explainable risk scoring
- prioritize and explain risks

### Phase 5
- add LangGraph orchestration
- connect graph tools and retrieval tools
- enable LangSmith tracing

### Phase 6
- build Streamlit MVP UI
- produce portfolio walkthrough

## Design principles
- canonical model first
- graph-native analysis
- deterministic outputs where possible
- LLMs augment reasoning, not truth
- versioned artifacts for reproducibility
- modular architecture for extensibility

## Running vision
Threat Forge AI is best understood not as “an AI that does threat modeling,” but as a **model-driven security analysis platform with agentic reasoning**.

## Next milestones
1. finalize schema v0.1
2. validate example TOML model
3. load graph into Neo4j
4. generate first structured threat set
5. compute first risk-ranked output
6. expose through LangGraph + Streamlit
```

---

## 8.2 `docs/one_page_architecture.md`

```md
# Threat Forge AI — One-Page Architecture

## Product statement
Threat Forge AI is a graph-native, model-driven threat modeling platform that transforms architecture evidence into a canonical security model, maps threats using MITRE ATT&CK and MITRE ATLAS, prioritizes them through an explainable risk engine, and exposes the results through agentic LLM workflows.

## Architectural intent
The platform is designed to demonstrate and eventually productize five capabilities:
1. canonical security modeling
2. graph-based system analysis
3. framework-aligned threat generation
4. explainable risk prioritization
5. agentic security interaction through LLM tooling

## End-to-end flow
```text
Raw inputs
(specs, informal descriptions, SBOM, code signals)
        ↓
Evidence extraction and normalization
        ↓
Canonical TOML system model
        ↓
Pydantic validation
        ↓
Neo4j graph loading
        ↓
Threat generation (ATT&CK / ATLAS)
        ↓
Risk scoring and prioritization
        ↓
LangGraph query workflows
        ↓
Streamlit analyst interface
```

## Core modules
### Intake and normalization
Collects source evidence and prepares structured facts for model updates.

### Canonical model
Represents workflows, modules, objects, trust boundaries, domains, and privilege levels in TOML.

### Graph layer
Loads the canonical model into Neo4j for traversal, relationship analysis, and attack-path reasoning.

### Threat engine
Uses graph patterns and framework knowledge to generate candidate threats.

### Risk engine
Scores and ranks threats using explainable factors such as exposure, privilege sensitivity, and data criticality.

### Agent layer
Uses LangGraph to orchestrate graph queries, retrieval, and response synthesis.

### Knowledge layer
Provides retrieval over ATT&CK, ATLAS, CWE, OWASP, and NIST materials.

## Design principles
- source-of-truth model before LLM reasoning
- graph-native structure for security analysis
- explainability over black-box automation
- modular architecture with clear upgrade paths
- local-first MVP with portfolio-ready transparency

## MVP boundary
### Included
- one demo domain
- manual TOML system model
- Pydantic validation
- graph loading
- threat generation
- risk scoring
- LangGraph query workflow
- Streamlit UI
- LangSmith traces

### Deferred
- large-scale automated ingestion
- multi-user auth and collaboration
- live sync from real environments
- full control/mitigation coverage engine
- product-grade deployment concerns

## Primary demo domain
AI-enabled fintech payment platform.

## Portfolio value
This MVP demonstrates:
- security architecture reasoning
- AI agent orchestration
- RAG-informed analysis
- graph-based modeling
- explainable security prioritization
```

---

## 8.3 `examples/fintech_ai_platform.toml`

```toml
[meta]
schema_version = "0.1"
model_id = "fintech-ai-demo"
last_updated = "2026-03-15"
author = "Michel Kinasz"

[system]
name = "Fintech AI Payment Platform"
description = "A mobile payment platform with AI-assisted fraud analysis"
criticality = "high"
industry = "financial-services"

[[security_domains]]
id = "client"
name = "Client Domain"
trust_level = "low"

[[security_domains]]
id = "edge"
name = "Edge/API Domain"
trust_level = "medium"

[[security_domains]]
id = "backend"
name = "Backend Services"
trust_level = "high"

[[security_domains]]
id = "ml"
name = "ML Domain"
trust_level = "medium"

[[privilege_levels]]
id = "public"
level = 0
description = "Unauthenticated or public access"

[[privilege_levels]]
id = "user"
level = 1
description = "Authenticated end-user privileges"

[[privilege_levels]]
id = "service"
level = 2
description = "Backend service privileges"

[[privilege_levels]]
id = "admin"
level = 3
description = "Administrative privileges"

[[modules]]
id = "mobile_app"
name = "Mobile App"
module_type = "client_application"
domain = "client"
privilege = "user"
internet_exposed = true
processes_sensitive_data = true
ai_relevant = false
description = "Customer mobile application"

[[modules]]
id = "api_gateway"
name = "API Gateway"
module_type = "gateway"
domain = "edge"
privilege = "service"
internet_exposed = true
processes_sensitive_data = true
ai_relevant = false

[[modules]]
id = "auth_service"
name = "Auth Service"
module_type = "identity_service"
domain = "backend"
privilege = "service"
internet_exposed = false
processes_sensitive_data = true
ai_relevant = false

[[modules]]
id = "payment_service"
name = "Payment Service"
module_type = "transaction_service"
domain = "backend"
privilege = "service"
internet_exposed = false
processes_sensitive_data = true
ai_relevant = false

[[modules]]
id = "fraud_model_service"
name = "Fraud Model Service"
module_type = "ml_service"
domain = "ml"
privilege = "service"
internet_exposed = false
processes_sensitive_data = true
ai_relevant = true

[[objects]]
id = "user_credentials"
name = "User Credentials"
object_type = "credential"
classification = "secret"
regulated = true
ai_relevant = false

[[objects]]
id = "payment_instruction"
name = "Payment Instruction"
object_type = "transaction_data"
classification = "confidential"
regulated = true
ai_relevant = false

[[objects]]
id = "fraud_features"
name = "Fraud Features"
object_type = "feature_vector"
classification = "confidential"
regulated = true
ai_relevant = true

[[datastores]]
id = "txn_db"
name = "Transaction Database"
store_type = "relational_database"
domain = "backend"
contains = ["payment_instruction"]
ai_relevant = false

[[datastores]]
id = "feature_store"
name = "Feature Store"
store_type = "feature_store"
domain = "ml"
contains = ["fraud_features"]
ai_relevant = true

[[external_actors]]
id = "customer"
name = "Customer"
actor_type = "end_user"

[[external_actors]]
id = "attacker"
name = "External Attacker"
actor_type = "threat_actor"

[[workflows]]
id = "user_login"
name = "User Login"
description = "Customer authenticates through mobile app"
steps = [
  "customer -> mobile_app",
  "mobile_app -> api_gateway",
  "api_gateway -> auth_service"
]
modules = ["mobile_app", "api_gateway", "auth_service"]
objects = ["user_credentials"]

[[workflows]]
id = "payment_execution"
name = "Payment Execution"
description = "Customer initiates payment and fraud checks are performed"
steps = [
  "customer -> mobile_app",
  "mobile_app -> api_gateway",
  "api_gateway -> payment_service",
  "payment_service -> fraud_model_service",
  "payment_service -> txn_db",
  "fraud_model_service -> feature_store"
]
modules = ["mobile_app", "api_gateway", "payment_service", "fraud_model_service"]
objects = ["payment_instruction", "fraud_features"]

[[trust_boundaries]]
id = "internet_boundary"
name = "Internet Boundary"
from_domain = "client"
to_domain = "edge"

[[trust_boundaries]]
id = "backend_ml_boundary"
name = "Backend to ML Boundary"
from_domain = "backend"
to_domain = "ml"

[[dependencies]]
source = "mobile_app"
target = "api_gateway"
relationship = "calls"

[[dependencies]]
source = "api_gateway"
target = "auth_service"
relationship = "calls"

[[dependencies]]
source = "api_gateway"
target = "payment_service"
relationship = "calls"

[[dependencies]]
source = "payment_service"
target = "fraud_model_service"
relationship = "calls"

[[dependencies]]
source = "payment_service"
target = "txn_db"
relationship = "writes"

[[dependencies]]
source = "fraud_model_service"
target = "feature_store"
relationship = "reads_writes"
```

---

## 8.4 `src/models/schema/canonical_model.py`

```python
from __future__ import annotations

from typing import List, Literal, Optional
from pydantic import BaseModel, Field


class Meta(BaseModel):
    schema_version: str
    model_id: str
    last_updated: str
    author: str


class System(BaseModel):
    name: str
    description: str
    criticality: Literal["low", "medium", "high", "critical"]
    industry: str


class SecurityDomain(BaseModel):
    id: str
    name: str
    trust_level: Literal["low", "medium", "high"]


class PrivilegeLevel(BaseModel):
    id: str
    level: int = Field(ge=0)
    description: str


class Module(BaseModel):
    id: str
    name: str
    module_type: str
    domain: str
    privilege: str
    internet_exposed: bool = False
    processes_sensitive_data: bool = False
    ai_relevant: bool = False
    description: Optional[str] = None


class ObjectModel(BaseModel):
    id: str
    name: str
    object_type: str
    classification: Literal["public", "internal", "confidential", "secret"]
    regulated: bool = False
    ai_relevant: bool = False


class DataStore(BaseModel):
    id: str
    name: str
    store_type: str
    domain: str
    contains: List[str] = []
    ai_relevant: bool = False


class ExternalActor(BaseModel):
    id: str
    name: str
    actor_type: str


class Workflow(BaseModel):
    id: str
    name: str
    description: str
    steps: List[str] = []
    modules: List[str] = []
    objects: List[str] = []


class TrustBoundary(BaseModel):
    id: str
    name: str
    from_domain: str
    to_domain: str


class Dependency(BaseModel):
    source: str
    target: str
    relationship: str


class CanonicalModel(BaseModel):
    meta: Meta
    system: System
    security_domains: List[SecurityDomain] = []
    privilege_levels: List[PrivilegeLevel] = []
    modules: List[Module] = []
    objects: List[ObjectModel] = []
    datastores: List[DataStore] = []
    external_actors: List[ExternalActor] = []
    workflows: List[Workflow] = []
    trust_boundaries: List[TrustBoundary] = []
    dependencies: List[Dependency] = []
```

---

## 8.5 GitHub Issues — 6-Week Execution Backlog

```md
# Epic 1 — Canonical Model Foundation

## Issue 1 — Define canonical TOML schema v0.1
**Goal:** create the first stable schema for systems, workflows, domains, modules, objects, and dependencies.

**Tasks:**
- define top-level sections
- define required vs optional fields
- freeze field naming conventions
- document schema assumptions

**Done when:**
- schema v0.1 is documented in `docs/domain_model.md`
- example TOML validates against the schema

## Issue 2 — Implement Pydantic canonical model
**Goal:** validate TOML models programmatically.

**Tasks:**
- implement Pydantic classes
- add enums / literals where appropriate
- add validation script
- create first validation test

**Done when:**
- `canonical_model.py` exists
- a validation script passes on the example model

## Issue 3 — Create fintech demo model
**Goal:** create one realistic demo system for the MVP.

**Tasks:**
- define modules and workflows
- define trust boundaries and dependencies
- define security-sensitive objects
- document why the scenario was chosen

**Done when:**
- `examples/fintech_ai_platform.toml` exists
- the scenario is documented in `docs/demo_scenario.md`

# Epic 2 — Graph Foundation

## Issue 4 — Define graph schema
**Goal:** map the canonical model into a Neo4j graph design.

**Tasks:**
- define node labels
- define relationship types
- define indexes and constraints
- document graph conventions

**Done when:**
- `docs/graph_schema.md` exists
- `src/graph/cypher/constraints.cypher` exists

## Issue 5 — Implement TOML-to-graph loader
**Goal:** load the canonical model into Neo4j.

**Tasks:**
- parse validated model
- create nodes and relationships
- make the load idempotent if possible
- add smoke test

**Done when:**
- graph loads successfully from example TOML
- core entities are queryable in Neo4j

## Issue 6 — Add sample graph queries
**Goal:** make the graph operational for analysis.

**Tasks:**
- create 8–12 Cypher queries
- validate query usefulness against the demo system
- store the best queries in `sample_queries.cypher`

**Done when:**
- an analyst can inspect attack surface and trust relationships

# Epic 3 — Threat Engine

## Issue 7 — Define threat generation heuristics
**Goal:** identify useful graph patterns that imply candidate threats.

**Tasks:**
- define exposure heuristics
- define trust-boundary heuristics
- define AI-specific heuristics
- map each heuristic to output fields

**Done when:**
- a methodology doc exists
- at least 6 meaningful rules are documented

## Issue 8 — Implement ATT&CK / ATLAS mapping
**Goal:** connect detected patterns to known techniques.

**Tasks:**
- define technique lookup structure
- create mapping helpers
- attach framework identifiers and names to outputs

**Done when:**
- generated threats include ATT&CK or ATLAS references

## Issue 9 — Generate structured threat outputs
**Goal:** produce analyst-readable threat objects.

**Tasks:**
- define threat output schema
- generate rationale strings
- write outputs to `models/outputs/threats/`

**Done when:**
- threat outputs can be inspected outside the UI

# Epic 4 — Risk Engine

## Issue 10 — Define explainable risk methodology
**Goal:** create a scoring model suitable for the MVP.

**Tasks:**
- choose factors and weights
- define normalization strategy
- define priority bands
- document trade-offs

**Done when:**
- `docs/risk_methodology.md` exists
- example threats can be scored consistently

## Issue 11 — Implement risk scoring module
**Goal:** convert threats into ranked risks.

**Tasks:**
- implement score calculation
- add explanations for top drivers
- store outputs in `models/outputs/risks/`

**Done when:**
- generated threats are ranked with readable justification

# Epic 5 — Agent Workflow

## Issue 12 — Define agent tools
**Goal:** expose graph and analysis capabilities as callable tools.

**Tasks:**
- create graph query tool
- create threat lookup tool
- create risk lookup tool
- define tool interfaces for LangGraph

**Done when:**
- tools can be called independently in local tests

## Issue 13 — Implement LangGraph query workflow
**Goal:** answer analyst questions against the model, graph, and outputs.

**Tasks:**
- define workflow state
- add routing logic
- connect tools
- produce grounded answers

**Done when:**
- the agent answers at least 5 representative questions

## Issue 14 — Add LangSmith observability
**Goal:** make the workflow inspectable and demoable.

**Tasks:**
- instrument traces
- test end-to-end runs
- capture example trace screenshots

**Done when:**
- traces are visible and useful during demo runs

# Epic 6 — Demo UI and Portfolio Polish

## Issue 15 — Build Streamlit MVP UI
**Goal:** provide a simple analyst-facing interface.

**Tasks:**
- add model overview page
- add threats page
- add risks page
- add analyst chat page

**Done when:**
- a user can run the demo locally and inspect outputs visually

## Issue 16 — Write portfolio-ready documentation
**Goal:** make the repo understandable and impressive.

**Tasks:**
- refine README
- add architecture and methodology docs
- add screenshots and sample prompts
- write a concise demo walkthrough

**Done when:**
- the repo tells a coherent AI + security story
```

