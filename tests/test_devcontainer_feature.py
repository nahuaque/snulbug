from __future__ import annotations

import json
import stat
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - exercised on Python 3.10.
    import tomli as tomllib  # type: ignore[import-not-found]

ROOT = Path(__file__).resolve().parents[1]
FEATURE_DIR = ROOT / "features" / "snulbug"


def test_devcontainer_feature_manifest_defines_runtime_modes_and_member_options():
    manifest = json.loads((FEATURE_DIR / "devcontainer-feature.json").read_text(encoding="utf-8"))
    options = manifest["options"]

    assert manifest["id"] == "snulbug"
    assert manifest["version"] == "0.1.0"
    assert options["mode"]["enum"] == ["cli", "gateway", "member-agent"]
    assert options["policy_profile"]["default"] == "tunnel-safe"
    assert options["install_source"]["enum"] == ["pypi", "github"]
    assert options["registry"]["default"] == ".snulbug/fabric-members.json"
    assert options["registry_key"]["default"] == "snulbug:fabric:members"
    assert options["member_upstream"]["default"] == "workspace=http://127.0.0.1:9000/mcp"


def test_devcontainer_feature_install_script_is_executable_and_installs_helpers():
    install = FEATURE_DIR / "install.sh"
    script = install.read_text(encoding="utf-8")
    mode = install.stat().st_mode

    assert mode & stat.S_IXUSR
    assert "snulbug-devcontainer-init" in script
    assert "snulbug-devcontainer-agent" in script
    assert "snulbug mcp fabric member agent" in script
    assert "snulbug mcp proxy --config snulbug.toml" in script
    assert "git+https://github.com/lbruhacs/snulbug" in script


def test_devcontainer_docs_and_feature_are_packaged():
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    include = pyproject["tool"]["hatch"]["build"]["targets"]["sdist"]["include"]
    docs = (ROOT / "docs" / "devcontainers.md").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    assert "features" in include
    assert "snulbug-devcontainer-init" in docs
    assert "snulbug-devcontainer-agent start" in docs
    assert "docs/devcontainers.md" in readme
