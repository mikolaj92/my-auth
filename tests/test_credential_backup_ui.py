"""Backup eligibility is not a promise about the user's current device."""

import dataclasses

import pytest
from app_factory.fastapi import AppFactoryUi, install_app_factory_ui
from fastapi import FastAPI
from fastapi.testclient import TestClient

from my_auth import PasskeyCredential, PasskeyUser, VerifiedRegistration
from my_auth.fastapi_htmx import PasskeyUiConfig, install_passkey_ui
from test_fastapi_htmx_adapter import _hooks, _service


@pytest.mark.parametrize(
    "device_type,backed_up,expected",
    [
        ("single_device", False, "Device-bound"),
        ("multi_device", False, "Backup eligible; not backed up"),
        ("multi_device", True, "Backed up"),
        ("unknown", False, "Backup status unknown"),
        ("single_device", True, "Backup status unknown"),
    ],
)
def test_backup_state_is_rendered_without_device_or_recovery_guarantees(
    device_type: str,
    backed_up: bool,
    expected: str,
) -> None:
    service = _service()
    user = PasskeyUser("owner", b"owner-handle", "owner")
    service.credentials.save_registration(
        VerifiedRegistration(
            user,
            PasskeyCredential(
                b"first",
                user.user_id,
                b"secret-public-key",
                device_type=device_type,
                backed_up=backed_up,
            ),
        )
    )
    app = FastAPI()

    platform = AppFactoryUi(
        "/static/platform", "app-factory-platform", "/static/platform"
    )
    install_app_factory_ui(app, environments=[])
    hooks = dataclasses.replace(_hooks(), get_session_user=lambda _request: user)
    install_passkey_ui(
        app, platform=platform, service=service, hooks=hooks, config=PasskeyUiConfig()
    )
    with TestClient(app) as client:
        response = client.get("/account/passkeys?lang=en")
        polish = client.get("/account/passkeys?lang=pl")
    polish_labels = {
        "Device-bound": "Przypisany do urządzenia",
        "Backup eligible; not backed up": "Możliwa kopia zapasowa; jeszcze niewykonana",
        "Backed up": "Kopia zapasowa wykonana",
        "Backup status unknown": "Nieznany stan kopii zapasowej",
    }
    assert polish_labels[expected] in polish.text
    assert response.status_code == 200
    assert expected in response.text
    assert "secret-public-key" not in response.text
    assert "This device" not in response.text
