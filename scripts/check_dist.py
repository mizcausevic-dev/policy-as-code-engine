"""Reject unexpected files in the release wheel and source archive."""

from __future__ import annotations

import tarfile
import zipfile
from pathlib import Path


def main() -> None:
    dist = Path("dist")
    sdists = list(dist.glob("*.tar.gz"))
    wheels = list(dist.glob("*.whl"))
    if len(sdists) != 1 or len(wheels) != 1:
        raise SystemExit("expected exactly one sdist and one wheel in dist/")

    with tarfile.open(sdists[0]) as archive:
        names = [member.name.partition("/")[2] for member in archive.getmembers()]
    if not names or any(not name for name in names):
        raise SystemExit("sdist has an invalid archive path")
    allowed_root = {".gitignore", "LICENSE", "README.md", "pyproject.toml", "PKG-INFO"}
    allowed_examples = {"examples/example-bundle.yaml", "examples/example-context.json"}
    unexpected_sdist = [
        name
        for name in names
        if name not in allowed_root
        and name not in allowed_examples
        and not (
            name.startswith("src/policy_as_code_engine/")
            and (name.endswith(".py") or name.endswith("/py.typed"))
        )
        and not (name.startswith("tests/") and name.endswith(".py"))
    ]
    if unexpected_sdist:
        raise SystemExit(f"unexpected sdist entries: {unexpected_sdist}")
    if "src/policy_as_code_engine/py.typed" not in names:
        raise SystemExit("sdist is missing py.typed")

    with zipfile.ZipFile(wheels[0]) as archive:
        wheel_names = archive.namelist()
    unexpected_wheel = [
        name
        for name in wheel_names
        if not name.startswith("policy_as_code_engine/") and not name.startswith("policy_as_code_engine-")
    ]
    if unexpected_wheel:
        raise SystemExit(f"unexpected wheel entries: {unexpected_wheel}")
    if "policy_as_code_engine/py.typed" not in wheel_names:
        raise SystemExit("wheel is missing py.typed")
    print(f"distribution contents passed: {len(names)} sdist files, {len(wheel_names)} wheel files")


if __name__ == "__main__":
    main()
