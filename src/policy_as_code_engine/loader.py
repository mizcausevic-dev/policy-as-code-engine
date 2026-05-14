"""
File loaders for `PolicyBundle`.

Supports JSON and YAML so operators can author bundles in whichever format
their tooling already speaks. The loader is intentionally thin — the heavy
lifting is in `models.PolicyBundle.model_validate`.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from .models import PolicyBundle


def load_bundle_from_string(raw: str, *, fmt: str | None = None) -> PolicyBundle:
    """
    Parse a serialized bundle. `fmt` may be `"json"` or `"yaml"`; if omitted
    the loader sniffs the leading character (`{` / `[` -> JSON, else YAML).
    """
    fmt = (fmt or _sniff(raw)).lower()
    if fmt == "json":
        parsed: Any = json.loads(raw)
    elif fmt in ("yaml", "yml"):
        parsed = yaml.safe_load(raw)
    else:
        raise ValueError(f"unsupported bundle format: {fmt!r}")
    return PolicyBundle.model_validate(parsed)


def load_bundle_from_file(path: str | Path) -> PolicyBundle:
    p = Path(path)
    raw = p.read_text(encoding="utf-8")
    fmt = "yaml" if p.suffix.lower() in (".yaml", ".yml") else "json"
    return load_bundle_from_string(raw, fmt=fmt)


def _sniff(raw: str) -> str:
    stripped = raw.lstrip()
    if stripped.startswith(("{", "[")):
        return "json"
    return "yaml"
