import socket
from unittest.mock import patch

import pytest

from app.alerting import validate_webhook_url, webhook_signature


def public_resolution(*args: object, **kwargs: object) -> list[tuple[object, ...]]:
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]


def private_resolution(*args: object, **kwargs: object) -> list[tuple[object, ...]]:
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))]


@patch("app.alerting.socket.getaddrinfo", public_resolution)
def test_webhook_url_requires_public_https_destination() -> None:
    assert validate_webhook_url("https://EXAMPLE.com/hooks/ot") == (
        "https://example.com/hooks/ot"
    )
    with pytest.raises(ValueError, match="HTTPS"):
        validate_webhook_url("http://example.com/hooks/ot")
    with pytest.raises(ValueError, match="credentials"):
        validate_webhook_url("https://user:password@example.com/hook")


@patch("app.alerting.socket.getaddrinfo", private_resolution)
def test_webhook_url_rejects_private_resolution() -> None:
    with pytest.raises(ValueError, match="public IP"):
        validate_webhook_url("https://internal.example/hook")


def test_webhook_signature_uses_sha256_hmac() -> None:
    assert webhook_signature("secret", b'{"event":"drift"}') == (
        "sha256=9cccea216ad05f9461a5dad652c6065c3885d84351edfc160cab18dcd806b6cb"
    )
