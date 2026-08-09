import pytest
from pydantic import SecretStr, ValidationError

from app.auth import AccessLevel, require_viewer
from app.config import Settings


def test_rejects_short_bootstrap_keys() -> None:
    with pytest.raises(ValidationError):
        Settings(
            _env_file=None,
            bootstrap_api_keys_enabled=True,
            viewer_api_key=SecretStr("short"),
            admin_api_key=SecretStr("also-short"),
        )


def test_bootstrap_access_level_with_dependency_override(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = Settings(
        _env_file=None,
        bootstrap_api_keys_enabled=True,
        viewer_api_key=SecretStr("viewer-key-that-is-long-enough"),
        admin_api_key=SecretStr("administrator-key-long-enough"),
    )
    monkeypatch.setattr("app.auth.get_settings", lambda: settings)
    principal = require_viewer(
        authorization=None,
        x_api_key="administrator-key-long-enough",
        session=None,  # type: ignore[arg-type]
    )
    assert principal.level == AccessLevel.ADMIN
