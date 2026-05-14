"""Unit tests for JSON / YAML bundle loading."""

from __future__ import annotations

from pathlib import Path

import pytest

from policy_as_code_engine.loader import load_bundle_from_file, load_bundle_from_string

_VALID_JSON = """
{
  "bundle_id": "demo",
  "policies": [
    {
      "id": "p",
      "rules": [
        {"id": "r", "effect": "allow", "when": {"kind": "always"}}
      ]
    }
  ]
}
"""

_VALID_YAML = """
bundle_id: demo
policies:
  - id: p
    rules:
      - id: r
        effect: allow
        when: {kind: always}
"""


class TestLoader:
    def test_json_load(self) -> None:
        bundle = load_bundle_from_string(_VALID_JSON, fmt="json")
        assert bundle.bundle_id == "demo"

    def test_yaml_load(self) -> None:
        bundle = load_bundle_from_string(_VALID_YAML, fmt="yaml")
        assert bundle.bundle_id == "demo"

    def test_sniffs_json(self) -> None:
        bundle = load_bundle_from_string(_VALID_JSON)
        assert bundle.bundle_id == "demo"

    def test_sniffs_yaml(self) -> None:
        bundle = load_bundle_from_string(_VALID_YAML)
        assert bundle.bundle_id == "demo"

    def test_unknown_format_raises(self) -> None:
        with pytest.raises(ValueError, match="unsupported"):
            load_bundle_from_string("{}", fmt="toml")

    def test_load_from_file(self, tmp_path: Path) -> None:
        p = tmp_path / "bundle.yaml"
        p.write_text(_VALID_YAML)
        bundle = load_bundle_from_file(p)
        assert bundle.bundle_id == "demo"
