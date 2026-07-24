from __future__ import annotations

from importlib.resources import files

from starlette.staticfiles import StaticFiles


def _passkey_ui_static_files() -> StaticFiles:
    return StaticFiles(directory=str(files("my_auth.fastapi_htmx").joinpath("static")))
