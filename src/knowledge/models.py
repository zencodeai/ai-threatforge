from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Tactic:
    tactic_id: str
    name: str
    framework: str
    domain: str
    shortname: str
    order: int


@dataclass(frozen=True)
class Technique:
    technique_id: str
    name: str
    framework: str
    domain: str
    description: str
    is_subtechnique: bool
    parent_id: str | None
    platforms: tuple[str, ...]
    tactics: tuple[str, ...]
    deprecated: bool
    url: str


@dataclass(frozen=True)
class Mitigation:
    mitigation_id: str
    name: str
    framework: str
    domain: str
    description: str
    technique_ids: tuple[str, ...]
