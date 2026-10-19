from __future__ import annotations

from email.message import Message
from pathlib import Path
from types import SimpleNamespace

import pytest

import snulbug.share as share
from snulbug import __version__
from snulbug.config import tomllib


@pytest.mark.parametrize("license_present", [True, False])
def test_installed_gateway_snapshot_uses_distribution_metadata_without_checkout(tmp_path, monkeypatch, license_present):
    site = tmp_path / "site-packages"
    package = site / "snulbug"
    package.mkdir(parents=True)
    (package / "share.py").write_text("# installed package source\n")
    (package / "assets").mkdir()
    (package / "assets" / "prism.js").write_text("// bundled asset\n")
    (package / "__pycache__").mkdir()
    (package / "__pycache__" / "share.pyc").write_bytes(b"cache must not be copied")
    license_path = Path(f"snulbug-{__version__}.dist-info/licenses/LICENSE")
    (site / license_path).parent.mkdir(parents=True)
    (site / license_path).write_text("MIT license fixture\n")
    metadata = Message()
    metadata["Summary"] = "Installed gateway fixture"
    metadata["Requires-Python"] = ">=3.10"
    metadata.set_payload("# Installed README\n")
    requires = ["httpx>=0.28,<1", "uvicorn>=0.30", 'redis>=5; extra == "redis"']
    dist = SimpleNamespace(
        version=__version__,
        metadata=metadata,
        requires=requires,
        files=[license_path] if license_present else [],
        locate_file=lambda entry: site / entry,
    )
    monkeypatch.setattr(share, "__file__", str(package / "share.py"))
    monkeypatch.setattr("importlib.metadata.distribution", lambda name: dist)
    output = tmp_path / "snapshot"
    if not license_present:
        with pytest.raises(FileNotFoundError, match="missing its LICENSE"):
            share._copy_gateway_source(output, force=False)
        return
    share._copy_gateway_source(output, force=False)
    project = tomllib.loads((output / "pyproject.toml").read_text())
    assert project["project"]["version"] == __version__
    assert project["project"]["dependencies"] == requires
    assert project["tool"]["hatch"]["build"]["targets"]["wheel"]["packages"] == ["snulbug"]
    assert (output / "README.md").read_text() == "# Installed README\n"
    assert (output / "LICENSE").read_text() == "MIT license fixture\n"
    assert (output / "snulbug" / "assets" / "prism.js").is_file()
    assert not (output / "snulbug" / "__pycache__").exists()
