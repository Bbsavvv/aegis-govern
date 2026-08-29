from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from aegis_core.config import get_settings
from aegis_core.store import get_store
from api.routers import acquisition, crosswalk, pipeline, remediation, telemetry

WEB_DIR = Path(__file__).resolve().parent.parent / "web"


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["Cache-Control"] = "no-store"
        return response


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title=settings.api_title,
        version=settings.api_version,
        description=(
            "Autonomous AI Governance & Security Enforcement Engine. "
            "Ingest telemetry, crosswalk against EU AI Act / GDPR / financial controls, "
            "stage remediation pull requests, and notarize acquisition proof-reports."
        ),
    )
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.include_router(telemetry.router)
    app.include_router(crosswalk.router)
    app.include_router(remediation.router)
    app.include_router(pipeline.router)
    app.include_router(acquisition.router)

    @app.get("/health")
    def health() -> dict:
        return {
            "status": "ok",
            "environment": settings.environment,
            "store": get_store().stats(),
        }

    @app.get("/")
    def dashboard() -> FileResponse:
        return FileResponse(WEB_DIR / "index.html")

    if WEB_DIR.is_dir():
        app.mount("/static", StaticFiles(directory=str(WEB_DIR)), name="static")

    return app


app = create_app()


def run() -> None:
    import uvicorn

    uvicorn.run("api.app:app", host="127.0.0.1", port=8080, reload=False)
