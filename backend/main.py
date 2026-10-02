from fastapi import FastAPI, Request
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from app.api.routes import router
from app.config.config import settings

app = FastAPI(title=settings.PROJECT_NAME)

app.include_router(router, prefix="/api")


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
def health_check():
    return {"status": "running", "project": settings.PROJECT_NAME}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
