from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.api.auth import router as auth_router
from src.api.config import settings, get_cors_origins

app = FastAPI(
    title=settings.APP_TITLE,
    description=settings.APP_DESCRIPTION,
    version=settings.APP_VERSION,
    contact={"name": "Team Status Reporter", "url": "https://example.com"},
    license_info={"name": "Proprietary"},
    openapi_tags=[
        {"name": "Auth", "description": "Authentication endpoints"},
    ],
)

# Configure CORS based on environment
allowed_origins = get_cors_origins(settings)
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins if allowed_origins else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/", summary="Health Check", tags=["Auth"])
def health_check():
    """Simple health check endpoint."""
    return {"message": "Healthy"}

# Register routers
app.include_router(auth_router)
