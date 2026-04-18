# Design — Mapping Rules & Sync UI

> Date: 2026-04-18
> Branch: `threat-methodology`
> Status: **Draft — pending review**

---

## 1. Motivation

The mapping pipeline (curated rules, tactic expansion, vector suggestions) and the
knowledge sync subsystem are currently CLI-only.  Analysts must drop to a terminal to:

- Check sync status or trigger a refresh.
- Browse curated and suggested technique mappings.
- Adjust mapping config (enable expansion, include suggestions).
- Promote a vector-suggested mapping to the curated rules file.

Adding these to the Streamlit UI gives analysts a self-service loop: **sync → review
suggestions → promote → re-run analysis** — without leaving the interface.

---

## 2. Scope

### In scope

| Feature | Description |
|---------|-------------|
| **Knowledge Status panel** | Read-only dashboard showing sync metadata (versions, counts, last sync time). Displayed in the sidebar. |
| **Sync Controls** | Sidebar controls to trigger `sync` with options (embed, map-heuristics, threshold, top-k). |
| **Mappings page** | New top-level page with three tabs: Curated, Suggested, Heuristics. |
| **Curated tab** | Table of all curated mappings from `mapping_rules.toml`, filterable by rule_id. |
| **Suggested tab** | Table of all suggested mappings from `mapping_suggestions.toml`, filterable by rule_id, sortable by composite_score. Promote action per row. |
| **Heuristics tab** | Read-only table of discovered heuristics with metadata (rule_id, name, frameworks, severity). |
| **Mapping Config editor** | Expander showing current `mapping_config.toml` settings with toggle controls for `include_suggested` and `expansion.enabled`. |
| **Promote action** | Move a suggested mapping into `mapping_rules.toml` (appends `[[mappings]]` entry, removes from suggestions file). |

### Out of scope

- Editing curated mapping rationale text inline (future).
- Creating brand-new heuristics from the UI.
- Deleting curated mappings from the UI (manual TOML edit for now).
- Real-time sync progress streaming (sync runs as a blocking subprocess).

---

## 3. UI Layout

### 3.1 Sidebar additions

The existing sidebar has: model selector, upload, Rebuild Analysis, page radio.

**Changes:**

```
┌─────────────────────────────┐
│  Example model  [▾ dropdown]│
│  Upload model (.toml)       │
│  ─────────────────────────  │
│  ### Knowledge Base         │
│  ATT&CK: v16.1  ATLAS: 4.1 │
│  Techniques: 830            │
│  Embeddings:  812           │
│  Suggestions: 47            │
│  Last sync: 2026-04-18 …    │
│  [Sync Now ▶]               │
│  ─────────────────────────  │
│  ### Rebuild Analysis       │
│  ☐ Clear graph before load  │
│  [Run Rebuild Workflow]     │
│  ─────────────────────────  │
│  Screen                     │
│  ◉ Model Overview           │
│  ○ Threats                  │
│  ○ Risks                   │
│  ○ Mappings          ← NEW │
│  ○ Chat                    │
└─────────────────────────────┘
```

The "Knowledge Base" section is always visible.  Clicking **Sync Now** opens an
expander with advanced options before executing.

### 3.2 Sync Controls (sidebar expander)

```
▸ Sync Options
  ATT&CK version: [latest     ]
  ATLAS version:  [latest     ]
  ☐ Generate embeddings
  ☐ Map heuristics
  Threshold: [0.40] (slider 0.10–0.90)
  Top-k:     [10  ] (slider 1–30)
  [Run Sync]
```

When **Map heuristics** is checked, **Generate embeddings** is forced on (greyed
out + checked), matching CLI behaviour.

### 3.3 Mappings page — three tabs

```
┌─────────────────────────────────────────────────────────────────┐
│  Mappings                                                       │
│  ┌──────────┬────────────┬─────────────┐                        │
│  │ Curated  │ Suggested  │ Heuristics  │                        │
│  └──────────┴────────────┴─────────────┘                        │
│                                                                  │
│  Filter: rule_id [All ▾]   framework [All ▾]                    │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ rule_id  technique_id  name        tactic     framework  │   │
│  │ TH-001   T1190         Exploit…    initial…   ATTACK     │   │
│  │ TH-001   T1078         Valid…      defense…   ATTACK     │   │
│  │ …                                                        │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
│  ▸ Mapping Configuration                                        │
│    include_suggested: ○ yes ● no                                │
│    expansion.enabled: ○ yes ● no                                │
│    [Save Config]                                                │
└─────────────────────────────────────────────────────────────────┘
```

**Suggested tab** adds a `score` column and a **Promote** button per row.

**Heuristics tab:**

```
┌───────────────────────────────────────────────────────────────────┐
│  rule_id  name                                frameworks  sev    │
│  TH-001   Internet exposed module …           ATTACK      high   │
│  TH-002   Dependency path from low-trust …    ATTACK      high   │
│  TH-004   AI-relevant dependencies …          ATLAS,ATT…  high   │
│  …                                                                │
│                                                                    │
│  6 heuristics discovered (4 TOML, 0 Python override)              │
└───────────────────────────────────────────────────────────────────┘
```

---

## 4. Component Design

### 4.1 New files

| File | Responsibility |
|------|---------------|
| `src/ui/pages/mappings.py` | Mappings page renderer (curated, suggested, heuristics tabs + config editor). |

### 4.2 Modified files

| File | Changes |
|------|---------|
| `src/ui/app.py` | Add "Mappings" to page radio. Import and render `mappings` page. Add sidebar knowledge-status panel and sync controls. |
| `src/ui/actions.py` | Add `sync_knowledge()` and `sync_status()` action wrappers. |
| `src/ui/data_access.py` | Add functions to load curated/suggested mappings, heuristics, and mapping config as UI-friendly row dicts. |
| `src/ui/pages/__init__.py` | Add `mappings` to `__all__`. |

### 4.3 Data access layer additions (`data_access.py`)

```python
def load_sync_status() -> dict[str, str]:
    """Wrapper around knowledge.sync.sync_status() — returns dict for sidebar."""

def curated_mapping_rows(rule_id: str | None = None) -> list[dict[str, str]]:
    """Load curated mappings from mapping_rules.toml, return flat dicts for st.dataframe."""

def suggested_mapping_rows(rule_id: str | None = None) -> list[dict[str, object]]:
    """Load suggested mappings from mapping_suggestions.toml with composite_score."""

def heuristic_rows() -> list[dict[str, str]]:
    """Return discovered heuristics as flat dicts."""

def load_mapping_config() -> dict[str, object]:
    """Load mapping_config.toml as a dict for the config editor."""
```

These functions call into the existing `mapping_loader` and `heuristics` modules
directly (in-process reads — no subprocess needed for read-only data).  This avoids
the overhead of spawning a CLI subprocess for every table render.

### 4.4 Action layer additions (`actions.py`)

```python
def sync_knowledge(
    *,
    attack_version: str = "latest",
    atlas_version: str = "latest",
    embed: bool = False,
    map_heuristics: bool = False,
    map_threshold: float = 0.40,
    map_top_k: int = 10,
    executor: Executor | None = None,
) -> ActionResult:
    """Run `threatforge sync` via subprocess with the given options."""

def get_sync_status(*, executor: Executor | None = None) -> ActionResult:
    """Run `threatforge sync --status` and return the output."""
```

Sync actions use subprocess (like existing `rebuild_analysis`) to avoid blocking
the Streamlit event loop with heavy embedding work and to keep the UI process lean.

### 4.5 Promote action

Promoting a suggested mapping:

1. **Append** a `[[mappings]]` entry to `mapping_rules.toml` with the suggestion's
   `rule_id`, `technique_id`, `framework`, `tactic`, and `rationale`.
2. **Remove** the corresponding entry from `mapping_suggestions.toml`.
3. Both operations are TOML file edits.

Implementation approach:

```python
# In data_access.py (or a new mapping_editor.py)

def promote_suggestion(
    rule_id: str,
    technique_id: str,
    *,
    rules_path: Path | None = None,
    suggestions_path: Path | None = None,
) -> bool:
    """Move a suggested mapping to curated.

    - Appends [[mappings]] block to mapping_rules.toml.
    - Removes the matching entry from mapping_suggestions.toml.
    - Returns True on success.
    """
```

Since TOML writing (especially removing an entry from an array-of-tables) is non-trivial
with `tomllib` (read-only), we use **line-level text manipulation** for the
suggestions file (it has a regular auto-generated format) and **append** for the
rules file.

**Safety:** Both files are under version control.  The promote action is reversible
via `git checkout`.  A `st.warning()` confirmation is shown before writing.

### 4.6 Mapping Config editor

The config editor reads `mapping_config.toml` and presents toggle controls for the
two boolean settings.  On "Save Config", it writes the full file back using TOML
serialization.

```python
def save_mapping_config(config: dict) -> None:
    """Write updated mapping_config.toml, preserving comments where possible."""
```

Since the config file is small and has a known structure, we rewrite it entirely
using a template approach (preserving the comment header).

---

## 5. Data Flow

### 5.1 Sync flow (UI)

```
[Sidebar: Sync Now]
    │
    ├─→ actions.sync_knowledge(embed=True, map_heuristics=True, …)
    │       └── subprocess: python -m cli.main sync --embed --map-heuristics …
    │           └── knowledge.sync.sync() → writes DB + mapping_suggestions.toml
    │
    ├─→ Display ActionResult (success/failure + stdout)
    │
    └─→ st.rerun() to refresh sidebar status metrics
```

### 5.2 Promote flow

```
[Suggested tab: Promote button for TH-004 / AML.T0099]
    │
    ├─→ st.warning("Promote TH-004 → AML.T0099 to curated?")
    │       └── [Confirm]
    │
    ├─→ data_access.promote_suggestion("TH-004", "AML.T0099")
    │       ├── append to mapping_rules.toml
    │       └── remove from mapping_suggestions.toml
    │
    └─→ st.rerun() to refresh tables
```

### 5.3 Page render flow

```
[Mappings page render]
    │
    ├─→ data_access.curated_mapping_rows()       → mapping_loader.load_curated_mappings()
    ├─→ data_access.suggested_mapping_rows()      → mapping_loader.load_suggested_mappings()
    ├─→ data_access.heuristic_rows()              → heuristics.discovered_heuristics()
    └─→ data_access.load_mapping_config()         → tomllib.load(mapping_config.toml)
```

---

## 6. Test Plan

### 6.1 New test file: `tests/test_ui_mappings.py`

| # | Test | Validates |
|---|------|-----------|
| 1 | `test_curated_mapping_rows_returns_all` | `curated_mapping_rows()` loads all 15 mappings from fixture TOML |
| 2 | `test_curated_mapping_rows_filters_by_rule` | Filter returns only TH-001 entries |
| 3 | `test_suggested_mapping_rows_empty_when_no_file` | Returns `[]` when suggestions file doesn't exist |
| 4 | `test_suggested_mapping_rows_loads_entries` | Parses fixture with 3 suggestions |
| 5 | `test_heuristic_rows_returns_discovered` | Returns 6 rows matching discovered heuristics |
| 6 | `test_load_mapping_config` | Returns dict with `expansion` and `suggestions` sections |
| 7 | `test_promote_suggestion_appends_to_rules` | After promote, new entry appears in rules file |
| 8 | `test_promote_suggestion_removes_from_suggestions` | After promote, entry is gone from suggestions file |
| 9 | `test_promote_nonexistent_returns_false` | Promote for unknown technique_id returns False |
| 10 | `test_sync_knowledge_action_builds_correct_args` | Verify subprocess args match options |
| 11 | `test_sync_knowledge_action_map_heuristics_flags` | When map_heuristics=True, embed is also passed |
| 12 | `test_save_mapping_config_roundtrip` | Save then re-load preserves values |
| 13 | `test_mappings_page_render_no_crash` | Smoke test: `mappings.render()` with fixture data |

### 6.2 Existing test updates

- `test_ui_actions.py`: Add tests for `sync_knowledge()` and `get_sync_status()` actions.

---

## 7. Implementation Plan

### Phase 1 — Data access & actions (no UI yet)

1. Add `curated_mapping_rows()`, `suggested_mapping_rows()`, `heuristic_rows()`,
   `load_mapping_config()` to `data_access.py`.
2. Add `sync_knowledge()`, `get_sync_status()` to `actions.py`.
3. Write tests 1–6, 10–11 from the test plan.
4. **Gate:** all tests pass.

### Phase 2 — Mappings page (read-only)

1. Create `src/ui/pages/mappings.py` with three tabs (curated, suggested, heuristics).
2. Wire into `app.py` (page radio, import).
3. Add mapping config viewer (read-only expander).
4. Write smoke test (test 13).
5. **Gate:** manual Streamlit run confirms tables render.

### Phase 3 — Sidebar sync controls

1. Add knowledge-status panel to sidebar in `app.py`.
2. Add sync-options expander with controls.
3. Wire "Run Sync" button to `actions.sync_knowledge()`.
4. **Gate:** manual test — sync from UI updates sidebar status.

### Phase 4 — Promote & config editor

1. Implement `promote_suggestion()` in `data_access.py`.
2. Add Promote button column in suggested tab.
3. Implement `save_mapping_config()`.
4. Add config editor toggles + Save button.
5. Write tests 7–9, 12.
6. **Gate:** promote flow works end-to-end, config save round-trips.

---

## 8. Conventions & Constraints

- **Subprocess for sync.** Sync may take 30+ seconds with embedding. Running it
  in-process would block the Streamlit event loop.  Subprocess matches the existing
  `rebuild_analysis` pattern.
- **In-process for reads.** Loading TOML files and calling `discovered_heuristics()`
  is fast and avoids subprocess overhead.
- **No new dependencies.** All functionality uses existing packages (streamlit,
  tomllib, pathlib).
- **TOML writing.** Python stdlib has `tomllib` (read-only) but no writer.
  We use template-based string building for the small, well-structured config file
  and line-append for rules.  No `tomli-w` dependency needed.
- **Frozen dataclasses / immutable returns.** Data access functions return
  `list[dict]` (Streamlit's preferred format for `st.dataframe`).
- **Test isolation.** All file operations in tests use `tmp_path` fixtures —
  never touch real `data/` files.
- **Executor injection.** Action functions accept `Executor` for testability,
  matching the existing pattern in `actions.py`.

---

## 9. Open Questions

| # | Question | Default if unanswered |
|---|----------|----------------------|
| 1 | Should promote require a confirmation dialog (two-click) or proceed immediately? | Two-click (safer) |
| 2 | Should the Mapping Config editor support editing `expansion.max_techniques_per_tactic` and `expansion.domains`? | No — only booleans for now |
| 3 | Should the sync status panel auto-refresh on page navigation? | Yes — call `sync_status()` on every render (cheap SQLite read) |
| 4 | Should we show the raw TOML in an expander (like threats/risks show raw JSON)? | Yes — for mapping_rules.toml and mapping_suggestions.toml |
