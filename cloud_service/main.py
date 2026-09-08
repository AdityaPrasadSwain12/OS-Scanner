"""ASGI module used by ``uvicorn cloud_service.main:app``."""

from .app import create_app

app = create_app()
