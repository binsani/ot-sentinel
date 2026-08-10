import importlib.util
from pathlib import Path


def load_verifier_module():
    path = Path(__file__).parents[2] / "scripts" / "verify-passive-release.py"
    spec = importlib.util.spec_from_file_location("verify_passive_release", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_repository_satisfies_passive_release_gate() -> None:
    module = load_verifier_module()

    assert module.verify_repository() == []


def test_gate_rejects_raw_sensor_transmit_path(tmp_path: Path) -> None:
    module = load_verifier_module()
    unsafe = tmp_path / "unsafe_sensor.py"
    unsafe.write_text(
        "import socket\nsocket.socket().connect(('192.0.2.1', 502))\n",
        encoding="utf-8",
    )

    violations = module.scan_python_file(unsafe, "sensor")

    assert any("forbidden sensor import: socket" in item for item in violations)
    assert any("forbidden sensor transmit call" in item for item in violations)


def test_gate_rejects_scapy_send_capability(tmp_path: Path) -> None:
    module = load_verifier_module()
    unsafe = tmp_path / "unsafe_scapy.py"
    unsafe.write_text("from scapy.all import sendp\n", encoding="utf-8")

    violations = module.scan_python_file(unsafe, "sensor")

    assert any("transmit-capable Scapy import" in item for item in violations)
