#!/usr/bin/env python3
"""
EFSF + FastAPI Integration Example

Demonstrates how to use EFSF for ephemeral session management
in a FastAPI application.

Run with: uvicorn fastapi_example:app --reload
"""

from datetime import datetime
from typing import Optional
from contextlib import asynccontextmanager

# FastAPI imports (install with: pip install fastapi uvicorn)
try:
    from fastapi import FastAPI, HTTPException, Depends, Header
    from pydantic import BaseModel
except ImportError:
    print("This example requires FastAPI. Install with: pip install fastapi uvicorn")
    exit(1)

from efsf import EphemeralStore, DataClassification, sealed


# =========================================================
# Configuration
# =========================================================

SESSION_TTL = "30m"  # Sessions expire after 30 minutes
STORE_BACKEND = "memory://"  # Use "redis://localhost:6379" for production


# =========================================================
# Models
# =========================================================

class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    session_id: str
    expires_at: datetime
    message: str


class SessionInfo(BaseModel):
    user_id: str
    username: str
    created_at: datetime
    expires_at: datetime
    access_count: int


class LogoutResponse(BaseModel):
    message: str
    destruction_certificate_id: Optional[str] = None


# =========================================================
# Application Setup
# =========================================================

# Global store instance
store: Optional[EphemeralStore] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize and cleanup the ephemeral store."""
    global store
    store = EphemeralStore(
        backend=STORE_BACKEND,
        default_ttl=SESSION_TTL,
        attestation=True,
    )
    print(f"✓ EFSF Store initialized ({STORE_BACKEND})")
    
    yield
    
    store.close()
    print("✓ EFSF Store closed")


app = FastAPI(
    title="EFSF Session Example",
    description="Ephemeral session management with automatic destruction",
    lifespan=lifespan,
)


# =========================================================
# Dependencies
# =========================================================

async def get_store() -> EphemeralStore:
    """Dependency to get the ephemeral store."""
    if store is None:
        raise HTTPException(500, "Store not initialized")
    return store


async def get_current_session(
    authorization: str = Header(..., description="Session ID"),
    ephemeral_store: EphemeralStore = Depends(get_store),
) -> dict:
    """
    Dependency to get and validate the current session.
    
    Sessions are stored as ephemeral records with automatic TTL.
    """
    session_id = authorization.replace("Bearer ", "")
    
    try:
        session_data = ephemeral_store.get(session_id)
        return {"session_id": session_id, **session_data}
    except Exception:
        raise HTTPException(401, "Invalid or expired session")


# =========================================================
# Endpoints
# =========================================================

@app.post("/login", response_model=LoginResponse)
async def login(
    request: LoginRequest,
    ephemeral_store: EphemeralStore = Depends(get_store),
):
    """
    Authenticate and create an ephemeral session.
    
    The session is automatically encrypted and will be destroyed
    after the TTL expires (30 minutes).
    """
    # In a real app, validate credentials against a database
    if request.username == "admin" and request.password == "secret":
        user_id = "user_001"
    else:
        raise HTTPException(401, "Invalid credentials")
    
    # Create ephemeral session
    session_data = {
        "user_id": user_id,
        "username": request.username,
        "created_at": datetime.utcnow().isoformat(),
        "roles": ["user", "admin"],
    }
    
    record = ephemeral_store.put(
        data=session_data,
        ttl=SESSION_TTL,
        classification=DataClassification.TRANSIENT,
        metadata={"login_ip": "127.0.0.1"},
    )
    
    return LoginResponse(
        session_id=record.id,
        expires_at=record.expires_at,
        message=f"Welcome, {request.username}! Session expires in 30 minutes.",
    )


@app.get("/me", response_model=SessionInfo)
async def get_current_user(
    session: dict = Depends(get_current_session),
    ephemeral_store: EphemeralStore = Depends(get_store),
):
    """
    Get current user information from the ephemeral session.
    """
    record = ephemeral_store._records.get(session["session_id"])
    
    return SessionInfo(
        user_id=session["user_id"],
        username=session["username"],
        created_at=datetime.fromisoformat(session["created_at"]),
        expires_at=record.expires_at if record else datetime.utcnow(),
        access_count=record.access_count if record else 0,
    )


@app.post("/logout", response_model=LogoutResponse)
async def logout(
    session: dict = Depends(get_current_session),
    ephemeral_store: EphemeralStore = Depends(get_store),
):
    """
    Logout and immediately destroy the session.
    
    Returns a destruction certificate as proof of session termination.
    """
    certificate = ephemeral_store.destroy(session["session_id"])
    
    return LogoutResponse(
        message="Session destroyed successfully",
        destruction_certificate_id=certificate.certificate_id if certificate else None,
    )


@app.get("/session/ttl")
async def get_session_ttl(
    session: dict = Depends(get_current_session),
    ephemeral_store: EphemeralStore = Depends(get_store),
):
    """Get remaining time before session expires."""
    remaining = ephemeral_store.ttl(session["session_id"])
    
    return {
        "session_id": session["session_id"],
        "remaining_seconds": remaining.total_seconds() if remaining else 0,
    }


@app.post("/sensitive-operation")
async def sensitive_operation(
    session: dict = Depends(get_current_session),
):
    """
    Example of a sealed operation that processes sensitive data.
    
    All local state is destroyed when the function completes.
    """
    @sealed(attestation=True)
    def process_sensitive_data(user_id: str) -> dict:
        # Simulate processing sensitive information
        # All local variables are destroyed on function exit
        secret_token = f"secret_{user_id}_token"
        return {
            "result": "processed",
            "user_id": user_id,
        }
    
    result = process_sensitive_data(session["user_id"])
    
    return {
        "operation": "complete",
        "result": result["result"],
        "destruction_certificate": result.get("_destruction_certificate", {}).get("certificate_id"),
    }


@app.get("/admin/stats")
async def get_stats(
    session: dict = Depends(get_current_session),
    ephemeral_store: EphemeralStore = Depends(get_store),
):
    """Get store statistics (admin only)."""
    if "admin" not in session.get("roles", []):
        raise HTTPException(403, "Admin access required")
    
    stats = ephemeral_store.stats()
    certs = ephemeral_store.list_certificates()
    
    return {
        **stats,
        "recent_destructions": [
            {
                "certificate_id": c.certificate_id,
                "resource_id": c.resource.resource_id,
                "timestamp": c.destruction_timestamp.isoformat(),
            }
            for c in certs[:10]
        ],
    }


# =========================================================
# Health Check
# =========================================================

@app.get("/health")
async def health_check(ephemeral_store: EphemeralStore = Depends(get_store)):
    """Health check endpoint."""
    return {
        "status": "healthy",
        "store": ephemeral_store.stats(),
    }


# =========================================================
# Main
# =========================================================

if __name__ == "__main__":
    import uvicorn
    
    print("""
╔════════════════════════════════════════════════════════════╗
║                 EFSF + FastAPI Example                     ║
╠════════════════════════════════════════════════════════════╣
║                                                            ║
║  Endpoints:                                                ║
║    POST /login        - Create ephemeral session           ║
║    GET  /me           - Get current user                   ║
║    POST /logout       - Destroy session (with certificate) ║
║    GET  /session/ttl  - Check remaining session time       ║
║    GET  /admin/stats  - Store statistics                   ║
║                                                            ║
║  Test with:                                                ║
║    curl -X POST http://localhost:8000/login \\              ║
║         -H "Content-Type: application/json" \\              ║
║         -d '{"username":"admin","password":"secret"}'      ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝
    """)
    
    uvicorn.run(app, host="0.0.0.0", port=8000)
