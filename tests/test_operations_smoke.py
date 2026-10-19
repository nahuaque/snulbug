from __future__ import annotations

import os

import pytest

import snulbug._operations_smoke as smoke
from snulbug import __version__
from snulbug.release_qa import OPERATIONS_SMOKE_SUCCESS


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX subprocess/signal support")
def test_operations_smoke_exercises_real_local_gateway(capsys, monkeypatch):
    monkeypatch.setattr("importlib.metadata.version", lambda _: __version__)
    smoke._installed_operations_smoke()
    assert OPERATIONS_SMOKE_SUCCESS in capsys.readouterr().out


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX subprocess/signal support")
def test_operations_smoke_cleans_children_after_failure(capsys, monkeypatch):
    monkeypatch.setattr("importlib.metadata.version", lambda _: __version__)
    processes = []
    original = smoke.subprocess.Popen

    def start(*args, **kwargs):
        process = original(*args, **kwargs)
        processes.append(process)
        return process

    def fail(*_, **__):
        raise RuntimeError("injected operations failure")

    monkeypatch.setattr(smoke.subprocess, "Popen", start)
    monkeypatch.setattr(smoke, "_exercise_gateway", fail)
    with pytest.raises(RuntimeError, match="injected operations failure"):
        smoke._installed_operations_smoke()
    assert processes and all(process.poll() is not None for process in processes)
    assert OPERATIONS_SMOKE_SUCCESS not in capsys.readouterr().out


def test_operations_smoke_rejects_mismatched_installed_metadata(monkeypatch):
    monkeypatch.setattr("importlib.metadata.version", lambda _: "0.0.0")
    monkeypatch.setattr(smoke.os, "name", "posix")
    with pytest.raises(RuntimeError, match="metadata and package versions differ"):
        smoke._installed_operations_smoke()
