from __future__ import annotations

import json

from snulbug import SnapshotStateStore, simulate_policy
from snulbug.promotion import diff_policies
from snulbug.simulator import main as simulator_main


def test_snapshot_state_store_records_initial_operations_and_final_state():
    store = SnapshotStateStore({"counter": "1", "gone": "yes"})

    assert store.get("counter") == "1"
    assert store.incr("counter", 2) == 3
    assert store.cas("missing", None, "created") is True
    assert store.delete("gone") is True

    assert store.snapshot() == {
        "initial_state": {"counter": "1", "gone": "yes"},
        "operations": [
            {"op": "get", "key": "counter", "value": "1", "hit": True},
            {"op": "incr", "key": "counter", "before": "1", "amount": 2, "after": "3", "ttl": None},
            {
                "op": "cas",
                "key": "missing",
                "before": None,
                "expected": None,
                "after": "created",
                "swapped": True,
                "ttl": None,
            },
            {"op": "delete", "key": "gone", "before": "yes", "deleted": True},
        ],
        "final_state": {"counter": "3", "missing": "created"},
    }


def test_simulate_policy_can_replay_with_state_snapshot(tmp_path):
    script = tmp_path / "policy.lua"
    script.write_text(
        """
        return function(request, context, state)
          local count = state.incr("delivery:" .. request.headers["x-delivery"], 1)
          if count > 1 then
            return { action = "reject", status = 409, body = "duplicate" }
          end
          return { action = "continue" }
        end
        """,
        encoding="utf-8",
    )

    result = simulate_policy(
        script,
        {"path": "/hook", "headers": {"x-delivery": "evt-1"}},
        state_snapshot={"initial_state": {"delivery:evt-1": "1"}},
    )

    assert result["action"] == "reject"
    assert result["state_snapshot"]["initial_state"] == {"delivery:evt-1": "1"}
    assert result["state_snapshot"]["final_state"] == {"delivery:evt-1": "2"}


def test_simulator_cli_accepts_state_snapshot(tmp_path, capsys):
    script = tmp_path / "policy.lua"
    request = tmp_path / "request.json"
    state = tmp_path / "state.json"
    script.write_text(
        """
        return function(request, context, state)
          local value = state.get("flag")
          return { action = "respond", status = 200, body = value }
        end
        """,
        encoding="utf-8",
    )
    request.write_text(json.dumps({"path": "/in", "headers": {}}), encoding="utf-8")
    state.write_text(json.dumps({"initial_state": {"flag": "enabled"}}), encoding="utf-8")

    status = simulator_main(["simulate", str(script), str(request), "--state", str(state), "--compact"])

    output = json.loads(capsys.readouterr().out)
    assert status == 0
    assert output["decision"]["body"] == "enabled"
    assert output["state_snapshot"]["operations"][0]["op"] == "get"


def test_diff_policies_uses_per_fixture_state_snapshots(tmp_path):
    old_policy = tmp_path / "old.lua"
    new_policy = tmp_path / "new.lua"
    fixtures = tmp_path / "fixtures"
    snapshots = tmp_path / "snapshots"
    fixtures.mkdir()
    snapshots.mkdir()
    old_policy.write_text(
        """
        return function(request, context, state)
          return { action = "continue" }
        end
        """,
        encoding="utf-8",
    )
    new_policy.write_text(
        """
        return function(request, context, state)
          if state.get("delivery:evt-1") ~= nil then
            return { action = "reject", status = 409, body = "duplicate" }
          end
          return { action = "continue" }
        end
        """,
        encoding="utf-8",
    )
    (fixtures / "duplicate.json").write_text(
        json.dumps({"path": "/hook", "headers": {"x-delivery": "evt-1"}}),
        encoding="utf-8",
    )
    (snapshots / "duplicate.json").write_text(
        json.dumps({"initial_state": {"delivery:evt-1": "seen"}}),
        encoding="utf-8",
    )

    result = diff_policies(old_policy, new_policy, fixtures, state_snapshots_path=snapshots)

    assert result["safe_to_promote"] is False
    assert result["regressions"][0]["new"]["state_snapshot"]["initial_state"] == {"delivery:evt-1": "seen"}
    assert result["regressions"][0]["reason"] == "action changed from continue to reject"
