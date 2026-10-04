from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.api.auth import router as auth_router
from backend.api.ai import router as ai_router
from backend.api.threats import router as threats_router
from backend.api.incidents import router as incidents_router
from backend.api.signatures import router as signatures_router
from backend.api.analytics import router as analytics_router
from backend.api.sources import router as sources_router
from backend.api.simulations import router as simulations_router
from backend.api.model import router as model_router
from backend.database.database import seed_database

app = FastAPI(title="Quantum Cyber Defense", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router, prefix="/api/auth")
app.include_router(ai_router, prefix="/api/ai")
app.include_router(threats_router, prefix="/api/threats")
app.include_router(incidents_router, prefix="/api/incidents")
app.include_router(signatures_router, prefix="/api/signatures")
app.include_router(analytics_router, prefix="/api/analytics")
app.include_router(sources_router, prefix="/api/sources")
app.include_router(simulations_router, prefix="/api/simulations")
app.include_router(model_router, prefix="/api/models")

@app.on_event("startup")
def startup_event():
    seed_database()

@app.get("/health")
def health_check():
    return {"status": "ok"}
