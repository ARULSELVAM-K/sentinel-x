"""Sentinel X security investigation tools: read-only operations on synthetic data.

All tools operate exclusively on simulated security event data. No real systems are queried.
These tools support the incident investigation workflow.
"""

from __future__ import annotations

from strands import tool

# =============================================================================
# SYNTHETIC SECURITY DATA FIXTURES
# =============================================================================

# Simulated user login history
LOGIN_HISTORY = {
    "user_001": [
        {"timestamp": "2026-10-21T08:15:00Z", "ip": "203.0.113.42", "location": "San Francisco, CA", "status": "success", "device": "MacBook Pro"},
        {"timestamp": "2026-10-21T08:16:00Z", "ip": "203.0.113.42", "location": "San Francisco, CA", "status": "failed", "device": "MacBook Pro"},
        {"timestamp": "2026-10-21T08:17:00Z", "ip": "203.0.113.42", "location": "San Francisco, CA", "status": "failed", "device": "MacBook Pro"},
        {"timestamp": "2026-10-21T08:18:00Z", "ip": "203.0.113.42", "location": "San Francisco, CA", "status": "failed", "device": "MacBook Pro"},
        {"timestamp": "2026-10-21T08:20:00Z", "ip": "198.51.100.78", "location": "London, UK", "status": "success", "device": "Windows PC"},
    ],
    "user_002": [
        {"timestamp": "2026-10-20T14:30:00Z", "ip": "45.33.32.156", "location": "Mumbai, IN", "status": "success", "device": "iPhone 15"},
        {"timestamp": "2026-10-21T09:00:00Z", "ip": "45.33.32.156", "location": "Mumbai, IN", "status": "success", "device": "iPhone 15"},
        {"timestamp": "2026-10-21T09:15:00Z", "ip": "45.33.32.156", "location": "Mumbai, IN", "status": "success", "device": "iPhone 15"},
        {"timestamp": "2026-10-21T09:16:00Z", "ip": "185.220.101.45", "location": "Berlin, DE", "status": "success", "device": "Unknown"},
    ],
    "user_003": [
        {"timestamp": "2026-10-19T10:00:00Z", "ip": "192.0.2.100", "location": "New York, NY", "status": "success", "device": "Dell Laptop"},
        {"timestamp": "2026-10-20T10:00:00Z", "ip": "192.0.2.100", "location": "New York, NY", "status": "success", "device": "Dell Laptop"},
        {"timestamp": "2026-10-21T10:00:00Z", "ip": "192.0.2.100", "location": "New York, NY", "status": "success", "device": "Dell Laptop"},
    ],
    "user_004": [
        {"timestamp": "2026-10-21T11:00:00Z", "ip": "104.244.76.13", "location": "Toronto, CA", "status": "success", "device": "MacBook Air"},
        {"timestamp": "2026-10-21T11:05:00Z", "ip": "104.244.76.13", "location": "Toronto, CA", "status": "success", "device": "MacBook Air"},
    ],
    "user_005": [
        {"timestamp": "2026-10-21T16:00:00Z", "ip": "89.123.45.67", "location": "Singapore, SG", "status": "success", "device": "Android Phone"},
        {"timestamp": "2026-10-21T16:01:00Z", "ip": "89.123.45.67", "location": "Singapore, SG", "status": "success", "device": "Android Phone"},
    ],
}

# Simulated IP reputation database
IP_REPUTATION = {
    "198.51.100.78": {"category": "suspicious", "score": 25, "reports": 15, "first_seen": "2026-09-01", "last_seen": "2026-10-21", "notes": "Known proxy, associated with credential stuffing"},
    "185.220.101.45": {"category": "malicious", "score": 10, "reports": 47, "first_seen": "2026-08-15", "last_seen": "2026-10-21", "notes": "Tor exit node, frequent brute force attempts"},
    "104.244.76.13": {"category": "clean", "score": 95, "reports": 0, "first_seen": "2026-01-01", "last_seen": "2026-10-21", "notes": "Known corporate IP range"},
    "45.33.32.156": {"category": "suspicious", "score": 45, "reports": 3, "first_seen": "2026-06-01", "last_seen": "2026-10-21", "notes": "VPN provider, moderate risk"},
    "203.0.113.42": {"category": "clean", "score": 85, "reports": 0, "first_seen": "2025-01-01", "last_seen": "2026-10-21", "notes": "Standard residential IP"},
    "192.0.2.100": {"category": "clean", "score": 90, "reports": 0, "first_seen": "2024-01-01", "last_seen": "2026-10-21", "notes": "Corporate network"},
    "89.123.45.67": {"category": "unknown", "score": 50, "reports": 0, "first_seen": "2026-10-21", "last_seen": "2026-10-21", "notes": "Newly observed IP"},
}

# Simulated privilege change history
PRIVILEGE_CHANGES = {
    "user_001": [
        {"timestamp": "2026-10-15T10:00:00Z", "action": "role_grant", "by": "admin", "role": "standard_user"},
        {"timestamp": "2026-10-21T08:25:00Z", "action": "role_grant", "by": "system", "role": "admin"},
    ],
    "user_002": [
        {"timestamp": "2026-10-10T09:00:00Z", "action": "role_grant", "by": "admin", "role": "standard_user"},
        {"timestamp": "2026-10-21T09:20:00Z", "action": "permission_add", "by": "user_002", "permission": "database_write"},
    ],
    "user_003": [
        {"timestamp": "2026-09-01T10:00:00Z", "action": "role_grant", "by": "admin", "role": "standard_user"},
    ],
    "user_004": [
        {"timestamp": "2026-10-21T11:00:00Z", "action": "role_grant", "by": "admin", "role": "standard_user"},
    ],
}

# Simulated asset inventory
ASSETS = {
    "laptop_001": {"owner": "user_001", "type": "laptop", "os": "macOS 14", "last_seen": "2026-10-21T08:20:00Z", "encrypted": True},
    "laptop_002": {"owner": "user_002", "type": "laptop", "os": "Windows 11", "last_seen": "2026-10-21T09:16:00Z", "encrypted": True},
    "laptop_003": {"owner": "user_003", "type": "laptop", "os": "Ubuntu 22.04", "last_seen": "2026-10-21T10:00:00Z", "encrypted": False},
    "server_001": {"owner": "infrastructure", "type": "server", "os": "RHEL 9", "last_seen": "2026-10-21T12:00:00Z", "encrypted": True},
}

# Simulated incident database
INCIDENTS = [
    {"id": "INC-2026-001", "type": "failed_login", "user": "user_001", "timestamp": "2026-10-21T08:16:00Z", "status": "investigating", "severity": "medium"},
    {"id": "INC-2026-002", "type": "privilege_escalation", "user": "user_001", "timestamp": "2026-10-21T08:25:00Z", "status": "investigating", "severity": "high"},
    {"id": "INC-2026-003", "type": "unusual_location", "user": "user_002", "timestamp": "2026-10-21T09:16:00Z", "status": "open", "severity": "medium"},
    {"id": "INC-2026-004", "type": "new_device", "user": "user_004", "timestamp": "2026-10-21T11:00:00Z", "status": "closed", "severity": "low"},
    {"id": "INC-2026-005", "type": "failed_login", "user": "user_005", "timestamp": "2026-10-21T16:00:00Z", "status": "open", "severity": "low"},
]


# =============================================================================
# INVESTIGATION TOOLS
# =============================================================================

@tool
def inspect_login_history(user_id: str) -> dict:
    """Look up the login history for a user by their user ID.
    
    Returns the recent login attempts including timestamp, IP, location, status, and device.
    Use this to identify unusual login patterns or suspicious activity.
    """
    history = LOGIN_HISTORY.get(user_id, [])
    if not history:
        return {"user_id": user_id, "error": "No login history found", "logins": []}
    return {"user_id": user_id, "logins": history, "count": len(history)}


@tool
def inspect_ip_reputation(ip_address: str) -> dict:
    """Look up the reputation score and threat intelligence for an IP address.
    
    Returns category (clean/suspicious/malicious), score (0-100), reports count,
    and threat intelligence notes. Use this to assess if an IP is associated with attacks.
    """
    rep = IP_REPUTATION.get(ip_address)
    if not rep:
        return {"ip": ip_address, "category": "unknown", "score": 50, "reports": 0, "notes": "No reputation data available"}
    return {"ip": ip_address, **rep}


@tool
def inspect_privilege_changes(user_id: str) -> dict:
    """Look up privilege and permission changes for a user.
    
    Returns role grants, permission additions, and other administrative changes.
    Use this to detect privilege escalation or unauthorized access attempts.
    """
    changes = PRIVILEGE_CHANGES.get(user_id, [])
    if not changes:
        return {"user_id": user_id, "changes": [], "note": "No privilege changes recorded"}
    return {"user_id": user_id, "changes": changes, "count": len(changes)}


@tool
def inspect_related_incidents(user_id: str) -> dict:
    """Search for other security incidents involving the same user.
    
    Returns all incidents in the database for the specified user.
    Use this to identify patterns or coordinated attacks.
    """
    related = [inc for inc in INCIDENTS if inc.get("user") == user_id]
    return {"user_id": user_id, "incidents": related, "count": len(related)}


@tool
def inspect_asset_context(user_id: str) -> dict:
    """Look up devices and assets associated with a user.
    
    Returns enrolled devices, operating systems, encryption status, and last seen times.
    Use this to verify if a login device is known and trusted.
    """
    user_assets = {k: v for k, v in ASSETS.items() if v.get("owner") == user_id}
    return {"user_id": user_id, "assets": user_assets, "count": len(user_assets)}


@tool
def conclude_investigation(incident_id: str, finding: str, recommended_action: str) -> dict:
    """Conclude the investigation with a finding and recommended action.
    
    This is the final step - records the investigation result and recommended response.
    Use this when investigation is complete and you have enough evidence.
    """
    return {
        "incident_id": incident_id,
        "finding": finding,
        "recommended_action": recommended_action,
        "investigated_at": "2026-10-21T12:00:00Z",
        "simulated": True
    }


@tool
def request_human_review(incident_id: str, reason: str) -> dict:
    """Request human security analyst review for an ambiguous case.
    
    Use this when the evidence is inconclusive or the risk is uncertain.
    A human analyst will review and decide the appropriate response.
    """
    return {
        "incident_id": incident_id,
        "reason": reason,
        "status": "pending_human_review",
        "requested_at": "2026-10-21T12:00:00Z",
        "simulated": True
    }


# Tool list for the agent
TOOLS = [
    inspect_login_history,
    inspect_ip_reputation,
    inspect_privilege_changes,
    inspect_related_incidents,
    inspect_asset_context,
    conclude_investigation,
    request_human_review,
]