from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Sequence

from .models import Mitigation, Tactic, Technique

_SCHEMA_SQL = """\
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tactics (
    tactic_id  TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    framework  TEXT NOT NULL,
    domain     TEXT NOT NULL,
    shortname  TEXT NOT NULL,
    sort_order INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS techniques (
    technique_id    TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    framework       TEXT NOT NULL,
    domain          TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    is_subtechnique INTEGER NOT NULL DEFAULT 0,
    parent_id       TEXT,
    platforms       TEXT NOT NULL DEFAULT '[]',
    deprecated      INTEGER NOT NULL DEFAULT 0,
    url             TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS technique_tactics (
    technique_id TEXT NOT NULL REFERENCES techniques(technique_id),
    tactic_id    TEXT NOT NULL REFERENCES tactics(tactic_id),
    PRIMARY KEY (technique_id, tactic_id)
);

CREATE TABLE IF NOT EXISTS mitigations (
    mitigation_id TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    framework     TEXT NOT NULL,
    domain        TEXT NOT NULL,
    description   TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS technique_mitigations (
    technique_id  TEXT NOT NULL REFERENCES techniques(technique_id),
    mitigation_id TEXT NOT NULL REFERENCES mitigations(mitigation_id),
    PRIMARY KEY (technique_id, mitigation_id)
);

CREATE INDEX IF NOT EXISTS idx_techniques_framework ON techniques(framework);
CREATE INDEX IF NOT EXISTS idx_techniques_domain ON techniques(domain);
CREATE INDEX IF NOT EXISTS idx_techniques_parent ON techniques(parent_id);
"""

DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "threat_intel" / "threatforge_kb.db"


class TechniqueStore:
    def __init__(self, db_path: Path | str = DEFAULT_DB_PATH):
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self._db_path))
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.executescript(_SCHEMA_SQL)

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> TechniqueStore:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    # ── Meta ─────────────────────────────────────────────────────────

    def set_meta(self, key: str, value: str) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)",
            (key, value),
        )
        self._conn.commit()

    def get_meta(self, key: str, default: str = "") -> str:
        row = self._conn.execute(
            "SELECT value FROM meta WHERE key = ?", (key,)
        ).fetchone()
        return row[0] if row else default

    # ── Bulk write (sync) ────────────────────────────────────────────

    def replace_all(
        self,
        *,
        tactics: Sequence[Tactic],
        techniques: Sequence[Technique],
        mitigations: Sequence[Mitigation],
    ) -> dict[str, int]:
        cur = self._conn.cursor()
        cur.execute("DELETE FROM technique_mitigations")
        cur.execute("DELETE FROM technique_tactics")
        cur.execute("DELETE FROM mitigations")
        cur.execute("DELETE FROM techniques")
        cur.execute("DELETE FROM tactics")

        cur.executemany(
            "INSERT INTO tactics (tactic_id, name, framework, domain, shortname, sort_order) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            [(t.tactic_id, t.name, t.framework, t.domain, t.shortname, t.order) for t in tactics],
        )

        cur.executemany(
            "INSERT INTO techniques "
            "(technique_id, name, framework, domain, description, is_subtechnique, parent_id, platforms, deprecated, url) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    t.technique_id, t.name, t.framework, t.domain, t.description,
                    int(t.is_subtechnique), t.parent_id,
                    json.dumps(list(t.platforms)), int(t.deprecated), t.url,
                )
                for t in techniques
            ],
        )

        tt_rows = []
        for tech in techniques:
            for tactic_shortname in tech.tactics:
                # Find tactic_id by shortname
                row = cur.execute(
                    "SELECT tactic_id FROM tactics WHERE shortname = ? AND framework = ?",
                    (tactic_shortname, tech.framework),
                ).fetchone()
                if row:
                    tt_rows.append((tech.technique_id, row[0]))
        cur.executemany(
            "INSERT OR IGNORE INTO technique_tactics (technique_id, tactic_id) VALUES (?, ?)",
            tt_rows,
        )

        cur.executemany(
            "INSERT INTO mitigations (mitigation_id, name, framework, domain, description) "
            "VALUES (?, ?, ?, ?, ?)",
            [(m.mitigation_id, m.name, m.framework, m.domain, m.description) for m in mitigations],
        )

        tm_rows = []
        for mit in mitigations:
            for tech_id in mit.technique_ids:
                tm_rows.append((tech_id, mit.mitigation_id))
        cur.executemany(
            "INSERT OR IGNORE INTO technique_mitigations (technique_id, mitigation_id) VALUES (?, ?)",
            tm_rows,
        )

        self._conn.commit()
        return {
            "tactics": len(tactics),
            "techniques": len(techniques),
            "mitigations": len(mitigations),
        }

    # ── Read ─────────────────────────────────────────────────────────

    def load_all_tactics(self) -> list[Tactic]:
        rows = self._conn.execute(
            "SELECT tactic_id, name, framework, domain, shortname, sort_order "
            "FROM tactics ORDER BY sort_order"
        ).fetchall()
        return [
            Tactic(
                tactic_id=r[0], name=r[1], framework=r[2],
                domain=r[3], shortname=r[4], order=r[5],
            )
            for r in rows
        ]

    def load_all_techniques(self) -> list[Technique]:
        rows = self._conn.execute(
            "SELECT technique_id, name, framework, domain, description, "
            "is_subtechnique, parent_id, platforms, deprecated, url "
            "FROM techniques ORDER BY technique_id"
        ).fetchall()

        # Pre-load tactic mappings
        tt_rows = self._conn.execute(
            "SELECT tt.technique_id, t.shortname FROM technique_tactics tt "
            "JOIN tactics t ON tt.tactic_id = t.tactic_id"
        ).fetchall()
        tactic_map: dict[str, list[str]] = {}
        for tech_id, shortname in tt_rows:
            tactic_map.setdefault(tech_id, []).append(shortname)

        return [
            Technique(
                technique_id=r[0], name=r[1], framework=r[2], domain=r[3],
                description=r[4], is_subtechnique=bool(r[5]), parent_id=r[6],
                platforms=tuple(json.loads(r[7])), deprecated=bool(r[8]),
                url=r[9], tactics=tuple(sorted(tactic_map.get(r[0], []))),
            )
            for r in rows
        ]

    def load_all_mitigations(self) -> list[Mitigation]:
        rows = self._conn.execute(
            "SELECT mitigation_id, name, framework, domain, description "
            "FROM mitigations ORDER BY mitigation_id"
        ).fetchall()

        tm_rows = self._conn.execute(
            "SELECT technique_id, mitigation_id FROM technique_mitigations"
        ).fetchall()
        tech_map: dict[str, list[str]] = {}
        for tech_id, mit_id in tm_rows:
            tech_map.setdefault(mit_id, []).append(tech_id)

        return [
            Mitigation(
                mitigation_id=r[0], name=r[1], framework=r[2], domain=r[3],
                description=r[4], technique_ids=tuple(sorted(tech_map.get(r[0], []))),
            )
            for r in rows
        ]

    def technique_count(self) -> int:
        row = self._conn.execute("SELECT COUNT(*) FROM techniques").fetchone()
        return row[0] if row else 0

    def is_populated(self) -> bool:
        return self.technique_count() > 0
