from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.v1.endpoints import auth

app = FastAPI(
    title="UniOS.ai Auth API",
    description="FastAPI Backend for Epic 1: User Authentication & Core Secure Platform Entry using Supabase Auth",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json"
)

# Configure CORS for frontend access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Adjust for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include Auth router
app.include_router(auth.router)

@app.get("/")
async def root():
    return {"message": "Welcome to UniOS.ai Auth API. Go to /api/docs for API documentation."}
