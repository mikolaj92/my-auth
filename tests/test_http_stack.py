"""Exercise the supported TestClient transport, not only dependency metadata."""

import importlib.util

from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient


def test_testclient_uses_httpx2_and_preserves_error_responses() -> None:
    assert importlib.util.find_spec("httpx2") is not None
    import httpx2

    app = FastAPI()

    @app.get("/denied")
    def denied():
        raise HTTPException(status_code=403, detail="denied")

    with TestClient(app) as client:
        assert isinstance(client, httpx2.Client)
        response = client.get("/denied")
    assert response.status_code == 403
    assert response.json() == {"detail": "denied"}
