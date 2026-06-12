from __future__ import annotations

import json

from snulbug import load_mcp_proxy_config, write_sample_config
from snulbug.config import merge_mcp_proxy_config
from snulbug.simulator import main as simulator_main


def test_load_mcp_proxy_config_resolves_relative_paths(tmp_path):
    config = tmp_path / "snulbug.toml"
    config.write_text(
        """
        [mcp.proxy]
        upstream = "http://127.0.0.1:9000"
        policy = "policy.snulbug/policy.lua"
        host = "127.0.0.1"
        port = 9090
        state = "sqlite:policy-state.sqlite3"
        trace = false
        record_out = "traces/session.jsonl"
        audit_out = "traces/audit.jsonl"
        redact_records = true
        decision_console = true
        decision_console_format = "json"
        max_body_bytes = 32768
        timeout = 5.5
        """,
        encoding="utf-8",
    )

    result = load_mcp_proxy_config(config)

    assert result["upstream"] == "http://127.0.0.1:9000"
    assert result["policy"] == tmp_path / "policy.snulbug/policy.lua"
    assert result["record_out"] == tmp_path / "traces/session.jsonl"
    assert result["audit_out"] == tmp_path / "traces/audit.jsonl"
    assert result["port"] == 9090
    assert result["trace"] is False
    assert result["redact_records"] is True
    assert result["decision_console"] is True
    assert result["decision_console_format"] == "json"


def test_load_mcp_proxy_config_supports_facade_upstreams(tmp_path):
    config = tmp_path / "snulbug.toml"
    config.write_text(
        """
        [mcp.proxy]
        policy = "policy.snulbug/policy.lua"

        [[mcp.proxy.upstreams]]
        name = "files"
        url = "http://127.0.0.1:9001/mcp"
        default = true

        [[mcp.proxy.upstreams]]
        name = "git"
        url = "http://127.0.0.1:9002/mcp"
        tool_prefix = "repo."
        """,
        encoding="utf-8",
    )

    result = load_mcp_proxy_config(config)

    assert result["upstreams"] == [
        {
            "name": "files",
            "url": "http://127.0.0.1:9001/mcp",
            "tool_prefix": "files.",
            "default": True,
        },
        {
            "name": "git",
            "url": "http://127.0.0.1:9002/mcp",
            "tool_prefix": "repo.",
            "default": False,
        },
    ]


def test_merge_mcp_proxy_config_ignores_none_and_applies_overrides(tmp_path):
    config = load_mcp_proxy_config(write_config(tmp_path))

    merged = merge_mcp_proxy_config(config, {"port": 8181, "host": None, "record_out": tmp_path / "override.jsonl"})

    assert merged["host"] == "127.0.0.1"
    assert merged["port"] == 8181
    assert merged["record_out"] == tmp_path / "override.jsonl"
    assert merged["redact_records"] is True


def test_write_sample_config_refuses_to_overwrite(tmp_path):
    config = tmp_path / "snulbug.toml"
    write_sample_config(config)

    try:
        write_sample_config(config)
    except FileExistsError as exc:
        assert "already exists" in str(exc)
    else:
        raise AssertionError("expected FileExistsError")


def test_mcp_config_init_cli_writes_config(tmp_path, capsys):
    config = tmp_path / "snulbug.toml"

    status = simulator_main(["mcp", "config", "init", "--output", str(config), "--compact"])

    output = json.loads(capsys.readouterr().out)
    assert status == 0
    assert output["ok"] is True
    assert config.is_file()
    assert load_mcp_proxy_config(config)["policy"] == tmp_path / "policy.snulbug/policy.lua"
    assert load_mcp_proxy_config(config)["redact_records"] is True


def test_mcp_proxy_cli_requires_policy_and_upstream_without_config(capsys):
    status = simulator_main(["mcp", "proxy", "--port", "9001"])

    captured = capsys.readouterr()
    assert status == 1
    assert "--policy and either --upstream or --facade-upstream are required" in captured.err


def test_mcp_proxy_cli_loads_config_before_running(monkeypatch, tmp_path):
    config = write_config(tmp_path)
    calls = []

    def fake_run_proxy(**kwargs):
        calls.append(kwargs)

    monkeypatch.setattr("snulbug.proxy.run_proxy", fake_run_proxy)

    status = simulator_main(["mcp", "proxy", "--config", str(config), "--port", "8181", "--no-trace"])

    assert status == 0
    assert calls[0]["upstream"] == "http://127.0.0.1:9000"
    assert calls[0]["policy"] == tmp_path / "policy.snulbug/policy.lua"
    assert calls[0]["port"] == 8181
    assert calls[0]["trace"] is False
    assert calls[0]["record_out"] == tmp_path / "traces/session.jsonl"
    assert calls[0]["redact_records"] is True
    assert calls[0]["decision_console"] is True
    assert calls[0]["decision_console_format"] == "json"


def test_mcp_proxy_cli_passes_facade_upstreams_without_config(monkeypatch, tmp_path):
    policy = tmp_path / "policy.lua"
    policy.write_text('return function() return { action = "continue" } end', encoding="utf-8")
    calls = []

    def fake_run_proxy(**kwargs):
        calls.append(kwargs)

    monkeypatch.setattr("snulbug.proxy.run_proxy", fake_run_proxy)

    status = simulator_main(
        [
            "mcp",
            "proxy",
            "--policy",
            str(policy),
            "--facade-upstream",
            "files=http://127.0.0.1:9001/mcp",
            "--facade-upstream",
            "git=http://127.0.0.1:9002/mcp",
        ]
    )

    assert status == 0
    assert calls[0]["upstreams"] == [
        {
            "name": "files",
            "url": "http://127.0.0.1:9001/mcp",
            "tool_prefix": "files.",
            "default": False,
        },
        {
            "name": "git",
            "url": "http://127.0.0.1:9002/mcp",
            "tool_prefix": "git.",
            "default": False,
        },
    ]


def test_mcp_proxy_cli_can_disable_record_redaction(monkeypatch, tmp_path):
    config = write_config(tmp_path)
    calls = []

    def fake_run_proxy(**kwargs):
        calls.append(kwargs)

    monkeypatch.setattr("snulbug.proxy.run_proxy", fake_run_proxy)

    status = simulator_main(["mcp", "proxy", "--config", str(config), "--no-redact-records"])

    assert status == 0
    assert calls[0]["redact_records"] is False


def write_config(tmp_path):
    config = tmp_path / "snulbug.toml"
    config.write_text(
        """
        [mcp.proxy]
        upstream = "http://127.0.0.1:9000"
        policy = "policy.snulbug/policy.lua"
        record_out = "traces/session.jsonl"
        audit_out = "traces/audit.jsonl"
        decision_console = true
        decision_console_format = "json"
        """,
        encoding="utf-8",
    )
    return config
