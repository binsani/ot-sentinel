import importlib.util
import json
from pathlib import Path

import pytest


def load_fetch_module():
    path = Path(__file__).parents[2] / "scripts" / "fetch-test-captures.py"
    spec = importlib.util.spec_from_file_location("fetch_test_captures", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_external_capture_manifest_has_complete_pinned_provenance() -> None:
    module = load_fetch_module()
    manifest = Path(__file__).parent / "external" / "manifest.json"

    fixtures = module.validate_manifest(json.loads(manifest.read_text(encoding="utf-8")))

    assert {fixture["filename"] for fixture in fixtures} == {
        "cisa_s7ident.pcap",
        "cisa_snap7.pcap",
        "dnp3_example.pcap",
        "modbus_write_single_coil.pcap",
        "opcua-encrypted.pcapng",
    }


def test_external_capture_manifest_rejects_mutable_url() -> None:
    module = load_fetch_module()
    fixture = {
        field: "value" for field in module.REQUIRED_FIELDS
    }
    fixture.update(
        filename="capture.pcap",
        url="https://example.test/main/capture.pcap",
        license_url="https://example.test/main/LICENSE",
        source_repository="https://github.com/example/repository",
        upstream_commit="a" * 40,
        sha256="b" * 64,
    )

    with pytest.raises(ValueError, match="unpinned url"):
        module.validate_manifest([fixture])
