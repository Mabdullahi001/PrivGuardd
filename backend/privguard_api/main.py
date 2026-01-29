from __future__ import annotations
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from privguard_api.settings import settings
from privguard_api.db.init_db import init_db
from privguard_api.routers import auth, gmail, scan, reports, messages

def create_app() -> FastAPI:
    app = FastAPI(title=settings.APP_NAME)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=[settings.FRONTEND_URL],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.on_event("startup")
    def _startup():
        init_db()

    app.include_router(auth.router)
    app.include_router(gmail.router)
    app.include_router(scan.router)
    app.include_router(reports.router)
    app.include_router(messages.router)

    @app.get("/api/health")
    def health():
        return {"status": "ok"}

    return app

app = create_app()
