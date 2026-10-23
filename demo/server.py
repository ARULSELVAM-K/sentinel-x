"""Sentinel X Demo UI: SOC Dashboard for Security Incident Investigation

This demo showcases Sentinel X using Strands Decider 2B for investigation tool selection,
paired with Amazon Bedrock for generative responses.

All security events are SIMULATED for demonstration purposes only.
"""

from __future__ import annotations

import json
import os
import uuid
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

from decider_kit.config import load_dotenv

load_dotenv()
STATIC = Path(__file__).parent / "static"
app = FastAPI(title="Sentinel X - AI Cyber Incident Commander")
_agent: Any = None


# =============================================================================
# INCIDENT SCENARIOS (Demo Data)
# =============================================================================

DEMO_INCIDENTS = [
    {
        "incident_id": "INC-2026-001",
        "type": "failed_login",
        "user": "user_001",
        "severity": "medium",
        "status": "investigating",
        "description": "Multiple failed login attempts followed by successful login from unusual location (London UK, from San Francisco IP)",
        "timestamp": "2026-10-21T08:20:00Z",
    },
    {
        "incident_id": "INC-2026-002",
        "type": "privilege_escalation",
        "user": "user_001",
        "severity": "high",
        "status": "investigating",
        "description": "Unusual privilege escalation - user granted admin role immediately after suspicious login",
        "timestamp": "2026-10-21T08:25:00Z",
    },
    {
        "incident_id": "INC-2026-003",
        "type": "unusual_location",
        "user": "user_002",
        "severity": "medium",
        "status": "open",
        "description": "Login from Berlin DE after regular logins from Mumbai IN (Tor exit node detected)",
        "timestamp": "2026-10-21T09:16:00Z",
    },
    {
        "incident_id": "INC-2026-004",
        "type": "new_device",
        "user": "user_003",
        "severity": "low",
        "status": "closed",
        "description": "New device login from known corporate location, regular time - benign pattern",
        "timestamp": "2026-10-21T10:00:00Z",
    },
    {
        "incident_id": "INC-2026-005",
        "type": "failed_login",
        "user": "user_005",
        "severity": "low",
        "status": "open",
        "description": "Single failed login attempt from Singapore - likely user error",
        "timestamp": "2026-10-21T16:00:00Z",
    },
]


# In-memory storage for investigation sessions
investigation_sessions: dict[str, dict] = {}


# =============================================================================
# API MODELS
# =============================================================================

class AnalyzeIncidentRequest(BaseModel):
    incident: dict[str, Any]
    session_id: str = "default"


class Turn(BaseModel):
    message: str
    session_id: str = "demo"
    images: list[str] = []


# =============================================================================
# AGENT INITIALIZATION
# =============================================================================

def agent() -> Any:
    global _agent
    if _agent is None:
        from agent.agent import SentinelX
        _agent = SentinelX()
    return _agent


# =============================================================================
# ROUTES
# =============================================================================

@app.get("/")
def index() -> FileResponse:
    return FileResponse(STATIC / "index.html")


@app.get("/api/info")
def info() -> dict[str, Any]:
    from decider_kit.config import settings

    s = settings()
    return {
        "agent": "Sentinel X - AI Cyber Incident Commander",
        "llm": "Amazon Bedrock",
        "decider": s.decider_mode,
        "target": "local",
        "pattern": "#tool-selection",
        "description": "Security incident investigation using Strands Decider 2B for tool selection"
    }


@app.get("/api/incidents")
def get_incidents(
    severity: str | None = None,
    status: str | None = None,
    search: str | None = None,
) -> dict[str, Any]:
    """Get all demo incidents with optional filtering."""
    filtered = DEMO_INCIDENTS.copy()
    
    if severity:
        filtered = [i for i in filtered if i.get("severity") == severity]
    if status:
        filtered = [i for i in filtered if i.get("status") == status]
    if search:
        search_lower = search.lower()
        filtered = [i for i in filtered if search_lower in i.get("incident_id", "").lower() 
                    or search_lower in i.get("description", "").lower()
                    or search_lower in i.get("user", "").lower()]
    
    return {
        "incidents": filtered,
        "total": len(filtered),
        "all_count": len(DEMO_INCIDENTS),
        "high_priority": sum(1 for i in DEMO_INCIDENTS if i.get("severity") == "high"),
        "critical": sum(1 for i in DEMO_INCIDENTS if i.get("severity") == "critical"),
        "investigating": sum(1 for i in DEMO_INCIDENTS if i.get("status") == "investigating"),
        "open": sum(1 for i in DEMO_INCIDENTS if i.get("status") == "open"),
        "completed": sum(1 for i in DEMO_INCIDENTS if i.get("status") == "completed"),
        "closed": sum(1 for i in DEMO_INCIDENTS if i.get("status") == "closed"),
    }


@app.get("/api/incidents/{incident_id}")
def get_incident(incident_id: str) -> JSONResponse:
    """Get detailed incident by ID."""
    incident = next((i for i in DEMO_INCIDENTS if i["incident_id"] == incident_id), None)
    if not incident:
        return JSONResponse({"error": "Incident not found"}, status_code=404)
    
    # Get investigation results if available
    investigation = investigation_sessions.get(incident_id)
    
    return JSONResponse({
        "incident": incident,
        "investigation": investigation,
    })


@app.post("/api/analyze")
def analyze_incident(req: AnalyzeIncidentRequest) -> JSONResponse:
    """Analyze a security incident using Sentinel X."""
    try:
        a = agent()
        result = a.analyze_incident(req.incident, session_id=req.session_id)
        
        # Store result in session for retrieval
        investigation_sessions[req.session_id] = result
        
        return JSONResponse(result)
    except Exception as e:
        return JSONResponse({"error": f"{type(e).__name__}: {e}"}, status_code=500)


@app.get("/api/investigation/{session_id}")
def get_investigation(session_id: str) -> JSONResponse:
    """Get the current investigation state for a session."""
    session_data = investigation_sessions.get(session_id)
    if not session_data:
        return JSONResponse({"error": "No investigation found for this session"}, status_code=404)
    return JSONResponse(session_data)


@app.post("/api/chat")
def chat(t: Turn) -> JSONResponse:
    """Chat with Sentinel X."""
    try:
        import inspect
        a = agent()
        sig = inspect.signature(a.chat)
        if t.images and "images" not in sig.parameters:
            return JSONResponse({"error": "this agent does not take images: add images=None to HackathonAgent.chat"}, status_code=400)
        return JSONResponse(a.chat(t.message, t.session_id, images=t.images if t.images else None))
    except Exception as e:
        return JSONResponse({"error": f"{type(e).__name__}: {e}"}, status_code=500)


@app.post("/api/reset")
def reset() -> dict[str, bool]:
    """Reset the agent and clear sessions."""
    global _agent
    _agent = None
    investigation_sessions.clear()
    return {"ok": True}


# =============================================================================
# HEALTH CHECK
# =============================================================================

@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "healthy", "service": "Sentinel X"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8501)