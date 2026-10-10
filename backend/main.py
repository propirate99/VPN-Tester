"""
Main FastAPI entry point for VajraNet AI.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.api.routes import router
from backend.database.db import init_db

app = FastAPI(
    title="VajraNet AI",
    description="Evidence-based IPsec VPN Security Analyzer & Threat Assessment API",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def startup_event():
    init_db()

app.include_router(router)

@app.get("/")
def root():
    return {
        "message": "Welcome to VajraNet AI - IPsec VPN Security Analyzer",
        "docs_url": "/docs",
        "health_check": "/health"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=True)
