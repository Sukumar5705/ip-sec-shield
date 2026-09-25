"""
main.py — FastAPI application entry point.

Responsibilities:
  - Create the FastAPI app instance
  - Include API router
  - Serve the frontend static files
  - Redirect root "/" to the frontend index.html
"""

from pathlib import Path
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes.ipsec import router as ipsec_router

# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------

app = FastAPI(
    title="IPsec Security Simulator",
    description=(
        "An educational simulation of IPsec AH and ESP security concepts. "
        "Demonstrates authentication, integrity, confidentiality, "
        "packet transmission, tampering, and verification."
    ),
    version="1.0.0",
)

# ---------------------------------------------------------------------------
# CORS — minimal, only needed if frontend is served from a different origin.
# When served from FastAPI itself (same origin) CORS is not required.
# ---------------------------------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8000", "http://127.0.0.1:8000"],
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)

# ---------------------------------------------------------------------------
# API routes — prefix /api so they never clash with static assets
# ---------------------------------------------------------------------------

app.include_router(ipsec_router, prefix="/api")

# ---------------------------------------------------------------------------
# Static frontend — served from frontend directory relative to repo root
# ---------------------------------------------------------------------------

FRONTEND_DIR = Path(__file__).resolve().parent.parent.parent / "frontend"


@app.get("/", include_in_schema=False)
def serve_index():
    """Serve the frontend SPA entry point."""
    return FileResponse(FRONTEND_DIR / "index.html")


@app.get("/{page}", include_in_schema=False)
def serve_spa_route(page: str):
    """Return the SPA entry point for client-side lab routes."""
    if page in {"protect", "transmit", "verify", "recover", "learn", "architecture", "about"}:
        return FileResponse(FRONTEND_DIR / "index.html")
    return FileResponse(FRONTEND_DIR / "index.html", status_code=404)


# Mount static assets AFTER the root route so the root route takes priority.
if FRONTEND_DIR.exists():
    app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")
