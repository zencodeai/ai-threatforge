from __future__ import annotations

import json
from typing import Any, Iterable


def toml_string(value: str) -> str:
    """Return *value* as a TOML-safe basic string."""
    return json.dumps(value)


def toml_array(values: Iterable[Any]) -> str:
    """Return *values* as a TOML array literal."""
    return "[" + ", ".join(toml_scalar(value) for value in values) + "]"


def toml_scalar(value: Any) -> str:
    """Return a TOML scalar literal for primitive values."""
    if isinstance(value, bool):
        return str(value).lower()
    if isinstance(value, str):
        return toml_string(value)
    return str(value)
