"""Tests for analysis.mapping_writer — suggestion generation and TOML output."""

from __future__ import annotations

from typing import Sequence

import numpy as np
import pytest

from knowledge.models import Tactic, Technique
from knowledge.store import TechniqueStore


# ── Helpers ──────────────────────────────────────────────────────


class FixedEmbedder:
    """Embedder that returns a predetermined vector for any input."""

    _model_name = "fixed-test-model"
    _dimensions = 4

    def __init__(self, fixed_query: np.ndarray) -> None:
        self._fixed = fixed_query

    @property
    def model_name(self) -> str:
        return self._model_name

    @property
    def dimensions(self) -> int:
        return self._dimensions

    def encode(self, texts: Sequence[str]) -> np.ndarray:
        return np.tile(self._fixed, (len(texts), 1))


def _norm(v: list[float]) -> np.ndarray:
    a = np.array(v, dtype=np.float32)
    return a / np.linalg.norm(a)


def _make_techniques() -> list[Technique]:
    return [
        Technique("T1190", "Exploit Public-Facing Application", "ATTACK", "enterprise",
                  "Exploit internet-facing software.",
                  False, None, ("Linux",), ("initial-access",), False, ""),
        Technique("T1021", "Remote Services", "ATTACK", "enterprise",
                  "Use remote services for lateral movement.",
                  False, None, ("Linux",), ("lateral-movement",), False, ""),
        Technique("T1485", "Data Destruction", "ATTACK", "enterprise",
                  "Destroy data to disrupt availability.",
                  False, None, ("Linux",), ("impact",), False, ""),
        Technique("AML.T0016", "Data Poisoning", "ATLAS", "atlas",
                  "Adversaries may poison training data.",
                  False, None, (), ("ml-attack-staging",), False, ""),
    ]


def _make_tactics() -> list[Tactic]:
    return [
        Tactic("TA0001", "Initial Access", "ATTACK", "enterprise", "initial-access", 0),
        Tactic("TA0008", "Lateral Movement", "ATTACK", "enterprise", "lateral-movement", 7),
        Tactic("TA0040", "Impact", "ATTACK", "enterprise", "impact", 12),
        Tactic("AML.TA0002", "ML Attack Staging", "ATLAS", "atlas", "ml-attack-staging", 1),
    ]


def _build_store(tmp_path, *, embed: bool = True):
    """Create a populated store with optional embeddings."""
    db = tmp_path / "writer_test.db"
    store = TechniqueStore(db)
    techniques = _make_techniques()
    store.replace_all(tactics=_make_tactics(), techniques=techniques, mitigations=[])

    if embed:
        query = _norm([1.0, 0.0, 0.0, 0.0])
        tech_vecs = {
            "T1190": _norm([0.9, 0.1, 0.0, 0.0]),
            "T1021": _norm([0.3, 0.7, 0.1, 0.0]),
            "T1485": _norm([0.0, 0.0, 0.1, 0.9]),
            "AML.T0016": _norm([0.5, 0.5, 0.0, 0.0]),
        }
        ids = list(tech_vecs.keys())
        vecs = np.stack([tech_vecs[tid] for tid in ids])
        hashes = [f"h_{tid}" for tid in ids]
        store.upsert_embeddings(
            entity_ids=ids,
            entity_type="technique",
            model_name="fixed-test-model",
            vectors=vecs,
            text_hashes=hashes,
        )

    return store


# ── _write_suggestions_toml ─────────────────────────────────────


def test_write_suggestions_toml_format(tmp_path):
    """Written TOML round-trips correctly via tomllib."""
    import tomllib

    from analysis.suggestion_scorer import ScoredSuggestion
    from analysis.mapping_writer import _write_suggestions_toml

    suggestions = [
        ("TH-001", ScoredSuggestion(
            technique_id="T1190",
            technique_name="Exploit Public-Facing Application",
            framework="ATTACK",
            tactic="initial-access",
            vector_score=0.85,
            tactic_bonus=0.15,
            framework_bonus=0.10,
            composite_score=0.56,
            explanation="Composite 0.560: vector=0.850, tactic-overlap=initial-access",
        )),
        ("TH-002", ScoredSuggestion(
            technique_id="T1021",
            technique_name="Remote Services",
            framework="ATTACK",
            tactic="lateral-movement",
            vector_score=0.70,
            tactic_bonus=0.0,
            framework_bonus=0.10,
            composite_score=0.435,
            explanation="Composite 0.435: vector=0.700",
        )),
    ]

    path = tmp_path / "suggestions.toml"
    _write_suggestions_toml(suggestions, path, threshold=0.40, top_k=10)

    assert path.exists()
    with open(path, "rb") as f:
        data = tomllib.load(f)

    assert len(data["mappings"]) == 2
    assert data["mappings"][0]["rule_id"] == "TH-001"
    assert data["mappings"][0]["technique_id"] == "T1190"
    assert data["mappings"][0]["mapping_type"] == "suggested"
    assert data["mappings"][0]["composite_score"] == pytest.approx(0.56, abs=0.001)
    assert data["mappings"][1]["rule_id"] == "TH-002"


def test_write_suggestions_toml_empty(tmp_path):
    """Empty suggestion list produces a valid but empty TOML."""
    import tomllib

    from analysis.mapping_writer import _write_suggestions_toml

    path = tmp_path / "empty.toml"
    _write_suggestions_toml([], path, threshold=0.40, top_k=10)

    assert path.exists()
    with open(path, "rb") as f:
        data = tomllib.load(f)
    assert data.get("mappings") is None or len(data.get("mappings", [])) == 0


def test_write_suggestions_toml_header_contains_params(tmp_path):
    """Header comment includes threshold and top-k."""
    from analysis.mapping_writer import _write_suggestions_toml

    path = tmp_path / "header.toml"
    _write_suggestions_toml([], path, threshold=0.35, top_k=5)

    content = path.read_text()
    assert "Threshold: 0.35" in content
    assert "Top-k: 5" in content
    assert "threatforge sync --map-heuristics" in content


# ── generate_mapping_suggestions ─────────────────────────────────


def test_generate_suggestions_empty_index(tmp_path, monkeypatch):
    """Returns _total=0 when no embeddings exist."""
    from analysis.mapping_writer import generate_mapping_suggestions

    store = _build_store(tmp_path, embed=False)
    output = tmp_path / "out.toml"

    # Patch embedder import to use our fixed embedder
    monkeypatch.setattr(
        "knowledge.embedder.SentenceTransformerEmbedder",
        lambda: FixedEmbedder(_norm([1.0, 0.0, 0.0, 0.0])),
    )

    counts = generate_mapping_suggestions(store, output_path=output)
    store.close()

    assert counts["_total"] == 0


def test_generate_suggestions_produces_output(tmp_path, monkeypatch):
    """Basic end-to-end: suggestions are written for discovered heuristics."""
    import tomllib

    from analysis.mapping_writer import generate_mapping_suggestions

    store = _build_store(tmp_path, embed=True)
    output = tmp_path / "suggestions.toml"
    embedder = FixedEmbedder(_norm([1.0, 0.0, 0.0, 0.0]))

    # Patch to use our fixed embedder and model name
    monkeypatch.setattr(
        "knowledge.embedder.SentenceTransformerEmbedder",
        lambda: embedder,
    )

    counts = generate_mapping_suggestions(
        store,
        threshold=0.0,  # accept everything
        top_k=5,
        output_path=output,
    )
    store.close()

    assert counts["_total"] > 0
    assert output.exists()

    with open(output, "rb") as f:
        data = tomllib.load(f)
    assert len(data["mappings"]) == counts["_total"]

    # Every entry should have mapping_type = "suggested"
    for m in data["mappings"]:
        assert m["mapping_type"] == "suggested"


def test_generate_suggestions_respects_threshold(tmp_path, monkeypatch):
    """High threshold filters out low-scoring suggestions."""
    from analysis.mapping_writer import generate_mapping_suggestions

    store = _build_store(tmp_path, embed=True)
    output = tmp_path / "suggestions.toml"
    embedder = FixedEmbedder(_norm([1.0, 0.0, 0.0, 0.0]))

    monkeypatch.setattr(
        "knowledge.embedder.SentenceTransformerEmbedder",
        lambda: embedder,
    )

    high = generate_mapping_suggestions(
        store, threshold=0.99, top_k=5, output_path=output,
    )
    store.close()

    # With threshold 0.99 most/all should be filtered out
    assert high["_total"] == 0 or high["_total"] < 4  # 4 techniques total


def test_generate_suggestions_excludes_curated(tmp_path, monkeypatch):
    """Curated mappings are excluded from suggestions."""
    import tomllib

    from analysis.mapping_writer import generate_mapping_suggestions

    store = _build_store(tmp_path, embed=True)
    output = tmp_path / "suggestions.toml"
    embedder = FixedEmbedder(_norm([1.0, 0.0, 0.0, 0.0]))

    monkeypatch.setattr(
        "knowledge.embedder.SentenceTransformerEmbedder",
        lambda: embedder,
    )

    counts = generate_mapping_suggestions(
        store, threshold=0.0, top_k=20, output_path=output,
    )
    store.close()

    with open(output, "rb") as f:
        data = tomllib.load(f)

    # Collect all (rule_id, technique_id) pairs from suggestions
    suggested_pairs = {(m["rule_id"], m["technique_id"]) for m in data["mappings"]}

    # Load curated mappings to compare
    from analysis.mapping_loader import load_curated_mappings
    curated = load_curated_mappings()
    curated_pairs = {(m.rule_id, m.technique_id) for m in curated}

    # No suggested pair should overlap with a curated pair
    overlap = suggested_pairs & curated_pairs
    assert len(overlap) == 0, f"Curated mappings found in suggestions: {overlap}"


# ── load_suggested_mappings ──────────────────────────────────────


def test_load_suggested_mappings_missing_file(tmp_path):
    """Returns empty tuple when file does not exist."""
    from analysis.mapping_loader import load_suggested_mappings

    result = load_suggested_mappings(suggestions_path=tmp_path / "nonexistent.toml")
    assert result == ()


def test_load_suggested_mappings_round_trip(tmp_path):
    """Suggestions written by _write_suggestions_toml can be read back."""
    from analysis.mapping_loader import load_suggested_mappings
    from analysis.mapping_writer import _write_suggestions_toml
    from analysis.suggestion_scorer import ScoredSuggestion

    suggestions = [
        ("TH-001", ScoredSuggestion(
            technique_id="T1190",
            technique_name="Exploit Public-Facing Application",
            framework="ATTACK",
            tactic="initial-access",
            vector_score=0.85,
            tactic_bonus=0.15,
            framework_bonus=0.10,
            composite_score=0.56,
            explanation="Composite 0.560: vector=0.850",
        )),
    ]

    path = tmp_path / "suggestions.toml"
    _write_suggestions_toml(suggestions, path, threshold=0.40, top_k=10)

    loaded = load_suggested_mappings(suggestions_path=path)
    assert len(loaded) == 1
    assert loaded[0].rule_id == "TH-001"
    assert loaded[0].technique_id == "T1190"
    assert loaded[0].mapping_type == "suggested"
    assert loaded[0].framework == "ATTACK"
    assert loaded[0].tactic == "initial-access"


def test_load_suggested_mappings_filters_by_rule_id(tmp_path):
    """Filtering by rule_id returns only matching entries."""
    from analysis.mapping_loader import load_suggested_mappings
    from analysis.mapping_writer import _write_suggestions_toml
    from analysis.suggestion_scorer import ScoredSuggestion

    suggestions = [
        ("TH-001", ScoredSuggestion("T1190", "Exploit", "ATTACK", "initial-access",
                                     0.85, 0.15, 0.10, 0.56, "test")),
        ("TH-002", ScoredSuggestion("T1021", "Remote", "ATTACK", "lateral-movement",
                                     0.70, 0.0, 0.10, 0.44, "test")),
    ]

    path = tmp_path / "suggestions.toml"
    _write_suggestions_toml(suggestions, path, threshold=0.40, top_k=10)

    th1 = load_suggested_mappings("TH-001", suggestions_path=path)
    assert len(th1) == 1
    assert th1[0].rule_id == "TH-001"

    th2 = load_suggested_mappings("TH-002", suggestions_path=path)
    assert len(th2) == 1
    assert th2[0].rule_id == "TH-002"

    none = load_suggested_mappings("TH-999", suggestions_path=path)
    assert none == ()


# ── sync() integration ───────────────────────────────────────────


def test_sync_map_heuristics_implies_embed(monkeypatch, tmp_path):
    """When map_heuristics=True, embed step must run even if embed=False."""
    import sys

    import knowledge.sync  # noqa: F401 — ensure module loaded
    sync_mod = sys.modules["knowledge.sync"]

    embed_called = False
    map_called = False

    def fake_embed(store, embedder=None):
        nonlocal embed_called
        embed_called = True
        return 0

    def fake_generate(store, *, threshold, top_k, output_path):
        nonlocal map_called
        map_called = True
        return {"_total": 0}

    # Patch sync internals to avoid real network/embedding calls
    monkeypatch.setattr(sync_mod, "fetch_attack_bundle", lambda *a, **kw: {"objects": []})
    monkeypatch.setattr(sync_mod, "parse_attack_bundle", lambda *a, **kw: ([], [], []))
    monkeypatch.setattr(sync_mod, "fetch_atlas_data", lambda *a, **kw: {"matrices": []})
    monkeypatch.setattr(sync_mod, "parse_atlas_data", lambda *a, **kw: ([], [], []))
    monkeypatch.setattr("knowledge.embedder.embed_techniques", fake_embed)
    monkeypatch.setattr("analysis.mapping_writer.generate_mapping_suggestions", fake_generate)

    db = tmp_path / "sync_test.db"
    counts = sync_mod.sync(map_heuristics=True, embed=False, db_path=db)

    assert embed_called, "embed_techniques should be called when map_heuristics=True"
    assert map_called, "generate_mapping_suggestions should be called"
    assert "suggestions" in counts


# ── load_suggestions_config ──────────────────────────────────────


def test_load_suggestions_config_defaults(tmp_path):
    """Returns defaults when config file does not exist."""
    from analysis.mapping_loader import load_suggestions_config

    result = load_suggestions_config(config_path=tmp_path / "nonexistent.toml")
    assert result["include_suggested"] is False


def test_load_suggestions_config_reads_section(tmp_path):
    """Reads [suggestions] section from config TOML."""
    from analysis.mapping_loader import load_suggestions_config

    config_path = tmp_path / "config.toml"
    config_path.write_text(
        '[suggestions]\ninclude_suggested = true\n'
        'suggestions_path = "custom/path.toml"\n',
        encoding="utf-8",
    )

    result = load_suggestions_config(config_path=config_path)
    assert result["include_suggested"] is True
    assert result["suggestions_path"] == "custom/path.toml"
