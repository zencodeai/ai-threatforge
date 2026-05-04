from __future__ import annotations

from pathlib import Path

from project_paths import ProjectPaths
from session_store import SessionStore
from ui import streamlit_app as ui_app


class _FakeSidebar:
    def __init__(self, *, selected_label: str, page: str, uploaded_file=None):
        self._selected_label = selected_label
        self._page = page
        self._uploaded_file = uploaded_file

    def selectbox(self, _label, _options, index=0):
        return self._selected_label

    def file_uploader(self, _label, type=None):
        return self._uploaded_file

    def radio(self, _label, _options, index=0):
        return self._page

    def markdown(self, *_args, **_kwargs):
        return None

    def caption(self, *_args, **_kwargs):
        return None

    def checkbox(self, _label, value=False, **_kwargs):
        return value

    def button(self, *_args, **_kwargs):
        return False

    def info(self, *_args, **_kwargs):
        return None

    def columns(self, count):
        return [_FakeMetricTarget() for _ in range(count)]

    def metric(self, *_args, **_kwargs):
        return None

    def expander(self, *_args, **_kwargs):
        return _FakeContextManager()


class _FakeMetricTarget:
    def metric(self, *_args, **_kwargs):
        return None


class _FakeContextManager:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class _FakeStreamlit:
    def __init__(self, *, selected_label: str = "(none)", page: str = "Model Overview", uploaded_file=None):
        self.sidebar = _FakeSidebar(selected_label=selected_label, page=page, uploaded_file=uploaded_file)
        self.infos: list[str] = []

    def set_page_config(self, **_kwargs):
        return None

    def title(self, *_args, **_kwargs):
        return None

    def info(self, message: str):
        self.infos.append(message)


def test_resolve_model_path_uses_session_when_no_new_selection(tmp_path: Path) -> None:
    paths = ProjectPaths.from_root(tmp_path)
    store = SessionStore(paths)
    model_path = tmp_path / "examples" / "demo.toml"
    model_path.parent.mkdir(parents=True, exist_ok=True)
    model_path.write_text("[meta]\nmodel_id='demo'\n", encoding="utf-8")
    store.set_model(model_path, model_id="demo")

    resolved = ui_app._resolve_model_path(None, None, session_store=store)

    assert resolved == model_path


def test_render_app_uses_session_model_for_model_overview(monkeypatch, tmp_path: Path) -> None:
    paths = ProjectPaths.from_root(tmp_path)
    store = SessionStore(paths)
    model_path = tmp_path / "examples" / "demo.toml"
    model_path.parent.mkdir(parents=True, exist_ok=True)
    model_path.write_text("[meta]\nmodel_id='demo'\n", encoding="utf-8")
    store.set_model(model_path, model_id="demo")

    fake_st = _FakeStreamlit(selected_label="(none)", page="Model Overview")
    captured: dict[str, Path] = {}

    monkeypatch.setattr(ui_app, "st", fake_st)
    monkeypatch.setattr(ui_app, "_render_knowledge_status", lambda **_kwargs: None)
    monkeypatch.setattr(ui_app, "_render_pipeline_controls", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(ui_app.model_overview, "render", lambda path: captured.setdefault("model_path", path))

    ui_app.render_app(paths=paths, session_store=store)

    assert captured["model_path"] == model_path
    assert not fake_st.infos
