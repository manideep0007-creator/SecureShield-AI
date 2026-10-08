import os
import uvicorn
from fastapi import FastAPI, Request
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from app.api.routes import router
from app.api.security import SecurityAndRateLimitMiddleware
from app.config.config import settings

app = FastAPI(title=settings.PROJECT_NAME)

app.add_middleware(SecurityAndRateLimitMiddleware)

app.include_router(router, prefix="/api")


def init_databases():
    """Ensure database directories and tables are initialized cleanly on startup."""
    try:
        from app.database.feedback import init_db as init_feedback_db
        from app.engines.sender_engine import init_db as init_sender_db
        init_feedback_db()
        init_sender_db()
    except Exception:
        pass

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
