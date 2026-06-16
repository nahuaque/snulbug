from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from snulbug import (
    CredentialBroker,
    apply_credential_header,
    credential_header,
    credential_metadata,
    credential_status,
    list_credential_brokers,
    normalize_fabric_credentials,
    register_credential_broker,
)


class FixtureCredentialBroker(CredentialBroker):
    type = "fixture"

    def normalize_source(
        self,
        entry: Mapping[str, Any],
        *,
        base_dir: Path,
        field: str,
        resolve_relative_paths: bool,
    ) -> Mapping[str, Any]:
        del base_dir, resolve_relative_paths
        name = entry.get("name")
        if not isinstance(name, str) or not name:
            raise ValueError(f"{field}.name must be a non-empty fixture credential name")
        return {"name": name}

    def resolve(self, credential: Mapping[str, Any]) -> str:
        return f"fixture-secret-for-{credential['name']}"

    def metadata(self, credential: Mapping[str, Any]) -> Mapping[str, Any]:
        return {"name": credential.get("name")}


def test_credential_broker_registry_accepts_custom_broker():
    register_credential_broker(FixtureCredentialBroker(), replace=True)

    credentials = normalize_fabric_credentials(
        {
            "upstream": {
                "type": "fixture",
                "name": "codespace",
                "scheme": "raw",
                "header": "x-fixture-token",
            }
        }
    )
    credential = credentials["upstream"]
    outgoing = apply_credential_header(
        {"x-fixture-token": "caller-value", "x-other": "ok"},
        credential,
    )

    assert "fixture" in list_credential_brokers()
    assert credential == {
        "id": "upstream",
        "type": "fixture",
        "name": "codespace",
        "scheme": "raw",
        "header": "x-fixture-token",
    }
    assert credential_header(credential) == ("x-fixture-token", "fixture-secret-for-codespace")
    assert outgoing == {"x-other": "ok", "x-fixture-token": "fixture-secret-for-codespace"}
    assert credential_metadata(credential) == {
        "id": "upstream",
        "type": "fixture",
        "source": "fixture",
        "scheme": "raw",
        "header": "x-fixture-token",
        "name": "codespace",
    }
    assert credential_status(credential) == {
        "id": "upstream",
        "type": "fixture",
        "source": "fixture",
        "scheme": "raw",
        "header": "x-fixture-token",
        "name": "codespace",
        "configured": True,
        "available": True,
    }
