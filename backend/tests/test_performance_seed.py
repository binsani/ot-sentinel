import importlib.util
from datetime import UTC, datetime
from pathlib import Path


def load_seed_module():
    path = Path(__file__).parents[2] / "scripts" / "seed-performance-data.py"
    spec = importlib.util.spec_from_file_location("performance_seed", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_synthetic_seen_times_always_respect_asset_constraint() -> None:
    module = load_seed_module()
    now = datetime.now(UTC)

    for index in range(10_000):
        first_seen, last_seen = module.synthetic_seen_times(index, now)
        assert first_seen <= last_seen <= now
