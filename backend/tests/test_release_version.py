import importlib.util
from pathlib import Path


def load_verifier_module():
    path = Path(__file__).parents[2] / "scripts" / "verify-release-version.py"
    spec = importlib.util.spec_from_file_location("verify_release_version", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_repository_versions_are_aligned_for_v1() -> None:
    module = load_verifier_module()

    assert module.verify("1.0.0", "v1.0.0") == []


def test_release_version_gate_rejects_wrong_tag_and_unstable_version() -> None:
    module = load_verifier_module()

    assert module.verify("1.0", "v1.0") == [
        "expected version is not stable semantic version: 1.0"
    ]
    assert "release tag is v1.0.1, expected v1.0.0" in module.verify("1.0.0", "v1.0.1")
