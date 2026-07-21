from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.routes.url_routes import router as url_router


app = FastAPI(
    title="AI Cyber Shield API",
    description=(
        "Explainable cybersecurity analysis for URLs, "
        "emails, and QR codes."
    ),
    version="0.1.0",
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


app.include_router(url_router)


@app.get("/", tags=["System"])
def root() -> dict[str, str]:
    return {
        "message": "AI Cyber Shield API is running.",
        "documentation": "/docs",
    }


@app.get("/health", tags=["System"])
def health_check() -> dict[str, str]:
    return {
        "status": "healthy",
    }