import asyncio
from contextlib import asynccontextmanager
import logging
import os
import sys
import uvicorn
from fastapi import FastAPI, Request
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from app.api.routes import router
from app.api.security import SecurityAndRateLimitMiddleware
from app.config.config import settings
from app.intelligence.threat_feeds import threat_store

logger = logging.getLogger(__name__)


async def run_threat_feed_sync_loop(interval_seconds: float = 6 * 3600):
    """
    Run threat_store.sync_live_feeds() automatically when the backend starts
    (in the background, non-blocking, failures logged and not fatal) and again every 6 hours.
    """
    while True:
        try:
            logger.info("Starting background threat intelligence feed sync...")
            result = await threat_store.sync_live_feeds()
            logger.info("Background threat intelligence feed sync completed: %s", result)
        except asyncio.CancelledError:
            break
        except Exception as exc:
            logger.warning("Background threat feed sync failed non-fatally: %s", exc)

        try:
            await asyncio.sleep(interval_seconds)
        except asyncio.CancelledError:
            break


def init_databases():
    """Ensure database directories and tables are initialized cleanly on startup."""
    try:
        from app.database.feedback import init_db as init_feedback_db
        from app.engines.sender_engine import init_db as init_sender_db
        from app.intelligence.threat_feeds import init_threat_db
        init_feedback_db()
        init_sender_db()
        init_threat_db()
    except Exception:
        pass


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_databases()
    # In automated tests, skip live external network sync unless explicitly enabled
    is_testing = "pytest" in sys.modules or os.getenv("PYTEST_CURRENT_TEST") is not None or os.getenv("TESTING") == "1"
    sync_task = None
    if not is_testing or os.getenv("ENABLE_TEST_BACKGROUND_SYNC") == "1":
        sync_task = asyncio.create_task(run_threat_feed_sync_loop())

    try:
        yield
    finally:
        if sync_task and not sync_task.done():
            sync_task.cancel()
            try:
                await sync_task
            except asyncio.CancelledError:
                pass


app = FastAPI(title=settings.PROJECT_NAME, lifespan=lifespan)

app.add_middleware(SecurityAndRateLimitMiddleware)

app.include_router(router, prefix="/api")

init_databases()


@app.exception_handler(RequestValidationError)
async def handle_request_validation_error(request: Request, exc: RequestValidationError):
    if request.url.path == "/api/feedback":
        return JSONResponse(
            status_code=422,
            content={
                "detail": {
                    "code": "invalid_feedback_request",
                    "message": "Feedback request is invalid.",
                }
            },
        )
    return await request_validation_exception_handler(request, exc)


@app.get("/")
@app.get("/health")
def health_check():
    return {
        "status": "running",
        "project": settings.PROJECT_NAME,
        "environment": settings.ENVIRONMENT
    }


if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=(settings.ENVIRONMENT == "development"))
