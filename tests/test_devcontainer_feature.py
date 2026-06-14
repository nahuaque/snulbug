from __future__ import annotations

import json
import stat
from pathlib import Path

from snulbug import load_mcp_proxy_config

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
    assert options["install_source"]["default"] == "github"
    assert options["extras"]["default"] == "discovery"
    assert options["registry"]["default"] == ".snulbug/fabric-members.json"
    assert options["registry_key"]["default"] == "snulbug:fabric:members"
    assert options["member_upstream"]["default"] == "workspace=http://127.0.0.1:9000/mcp"
    assert "codespaces:NAME:PORT[:PATH]" in options["member_upstream"]["description"]


def test_devcontainer_feature_install_script_is_executable_and_installs_helpers():
    install = FEATURE_DIR / "install.sh"
    script = install.read_text(encoding="utf-8")
    mode = install.stat().st_mode

    assert mode & stat.S_IXUSR
    assert "snulbug-devcontainer-init" in script
    assert "snulbug-devcontainer-agent" in script
    assert "snulbug mcp fabric member agent" in script
    assert "snulbug mcp share run --config snulbug.toml" in script
    assert "git+https://github.com/lbruhacs/snulbug" in script
    assert 'if [ -z "${SNULBUG_DEVCONTAINER_REGISTRY+x}" ]' in script
    assert "resolve_member_upstream" in script
    assert "GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN" in script
    assert "codespaces:NAME:PORT[:PATH]" in script


def test_devcontainer_docs_and_feature_are_packaged():
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    include = pyproject["tool"]["hatch"]["build"]["targets"]["sdist"]["include"]
    docs = (ROOT / "docs" / "devcontainers.md").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    assert "features" in include
    assert "snulbug-devcontainer-init" in docs
    assert "snulbug-devcontainer-agent start" in docs
    assert "codespaces:files:9001:/mcp" in docs
    assert "docs/devcontainers.md" in readme


def test_codespace_local_gateway_example_documents_member_agent_flow(monkeypatch):
    example = ROOT / "examples" / "codespace_local_gateway"
    devcontainer = json.loads((example / ".devcontainer" / "devcontainer.json").read_text(encoding="utf-8"))
    env_config = tomllib.loads((example / "snulbug.env-gateway.toml").read_text(encoding="utf-8"))
    config = tomllib.loads((example / "snulbug.local-gateway.toml").read_text(encoding="utf-8"))
    readme = (example / "README.md").read_text(encoding="utf-8")

    monkeypatch.setenv(
        "SNULBUG_DISCOVERY_UPSTREAMS",
        json.dumps(
            [
                {
                    "name": "codespace-files",
                    "url": "https://example-9001.app.github.dev/mcp",
                    "tool_prefix": "codespace.files.",
                }
            ]
        ),
    )
    loaded_env_config = load_mcp_proxy_config(example / "snulbug.env-gateway.toml")

    feature_options = devcontainer["features"]["ghcr.io/lbruhacs/snulbug/features/snulbug:0.1.0"]
    env_provider = env_config["mcp"]["fabric"]["discovery"]["providers"][0]
    provider = config["mcp"]["fabric"]["discovery"]["providers"][0]

    assert env_provider["type"] == "env"
    assert env_provider["env"] == "SNULBUG_DISCOVERY_UPSTREAMS"
    assert env_config["mcp"]["proxy"]["policy"] == "policy.lua"
    assert loaded_env_config["policy"] == example / "policy.lua"
    assert loaded_env_config["record_out"] == example / "traces/codespace-env-session.jsonl"
    assert loaded_env_config["event_sinks"][0]["type"] == "audit_jsonl"
    assert loaded_env_config["event_sinks"][0]["path"] == example / "traces/codespace-env-audit.jsonl"
    assert loaded_env_config["upstreams"][0]["name"] == "codespace-files"
    assert loaded_env_config["upstreams"][0]["tool_prefix"] == "codespace.files."
    assert feature_options["mode"] == "member-agent"
    assert feature_options["member_upstream"] == "codespaces:files:9001:/mcp"
    assert feature_options["registry_key"] == "snulbug:fabric:codespaces:members"
    assert provider["type"] == "members"
    assert provider["state_key"] == "snulbug:fabric:codespaces:members"
    assert config["mcp"]["proxy"]["policy"] == "policy.lua"
    assert "Demo A: One Codespace URL" in readme
    assert "snulbug mcp share codespace serve-demo" in readme
    assert "snulbug mcp share codespace attach" in readme
    assert ".snulbug/codespace-local/traces/audit.jsonl" in readme
    assert "SNULBUG_DISCOVERY_UPSTREAMS" in readme
    assert "codespace.files.list_project_files" in readme
    assert "uv run snulbug mcp fabric discover" in readme
    assert "CODESPACE_NAME" in readme
