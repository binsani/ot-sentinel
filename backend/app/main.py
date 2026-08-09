from collections.abc import Awaitable, Callable

from fastapi import FastAPI, Request
from starlette.responses import Response

from app.admin import router as admin_router
from app.config import get_settings
from app.exports import router as exports_router
from app.ingestion import router as ingestion_router
from app.inventory import router as inventory_router

app = FastAPI(
    title=get_settings().app_name,
    version="0.1.0",
    description="Passive OT/ICS asset inventory and vulnerability correlation API.",
)
app.include_router(ingestion_router)
app.include_router(inventory_router)
app.include_router(exports_router)
app.include_router(admin_router)


@app.middleware("http")
async def security_headers(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cache-Control"] = "no-store"
    if request.url.scheme == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


@app.get("/health", tags=["operations"])
def health() -> dict[str, str]:
    return {"status": "ok"}
