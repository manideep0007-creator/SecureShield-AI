from fastapi import FastAPI
from app.api.routes import router
from app.config.config import settings

app = FastAPI(title=settings.PROJECT_NAME)

app.include_router(router, prefix="/api")

@app.get("/")
def health_check():
    return {"status": "running", "project": settings.PROJECT_NAME}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
