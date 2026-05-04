from __future__ import annotations

from pathlib import Path

from analysis.snapshot_resolver import ThreatSnapshotResolver
from analysis.threat_outputs import build_threat_report_from_snapshot
from models.schema.canonical_model import load_canonical_model

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE_MODEL = ROOT / "examples" / "fintech_ai_platform.toml"


class _FakeQueries:
    pass


def test_snapshot_resolver_caches_fetches() -> None:
    calls: list[str] = []
    resolver = ThreatSnapshotResolver(
        _FakeQueries(),  # type: ignore[arg-type]
        fetchers={
            "internet_modules": lambda _queries: calls.append("internet_modules") or [{"module_id": "api_gateway"}],
        },
    )

    first = resolver["internet_modules"]
    second = resolver["internet_modules"]

    assert first == second
    assert calls == ["internet_modules"]
    assert resolver.resolved_keys() == ("internet_modules",)


def test_build_threat_report_preloads_only_materializer_dependencies(monkeypatch) -> None:
    model = load_canonical_model(EXAMPLE_MODEL)
    calls: list[str] = []
    resolver = ThreatSnapshotResolver(
        _FakeQueries(),  # type: ignore[arg-type]
        fetchers={
            "internet_modules": lambda _queries: calls.append("internet_modules") or [],
            "sensitive_workflows": lambda _queries: calls.append("sensitive_workflows") or [],
        },
    )

    class _FakeMaterializer:
        rule_id = "TH-001"
        required_snapshot_keys = ("internet_modules",)

        def materialize(
            self,
            rule,
            model,
            snapshot,
            *,
            now,
            technique_refs_fn,
            stable_id_fn,
            sorted_unique_fn,
        ):
            assert snapshot["internet_modules"] == []
            return []

    import analysis.threat_outputs as threat_outputs

    monkeypatch.setattr(threat_outputs, "all_materializers", lambda: [_FakeMaterializer()])

    report = build_threat_report_from_snapshot(model, resolver)

    assert report.threat_count == 0
    assert calls == ["internet_modules"]
