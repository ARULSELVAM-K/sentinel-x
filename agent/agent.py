"""Sentinel X: AI Cyber Incident Commander

A security operations agent that investigates simulated security incidents
using Strands Decider 2B to select investigation actions, paired with
Amazon Bedrock for generative responses.

All security events are simulated. No real systems are queried or affected.

    from agent.agent import SentinelX
    result = SentinelX().analyze_incident({
        "incident_id": "INC-001",
        "type": "failed_login",
        "user": "user_001",
        "severity": "medium",
        "description": "Multiple failed login attempts followed by successful login from unusual location"
    })
"""

from __future__ import annotations

import json
import time
from typing import Any

from strands import Agent

from decider_kit import Decider
from decider_kit.llm import agent_model, default_model_id, strip_thinking

from .decision import IncidentInvestigator, PATTERN_TAG
from .tools import TOOLS

NAME = "Sentinel X - AI Cyber Incident Commander"
SYSTEM_PROMPT = """You are Sentinel X, an AI Cyber Incident Commander for a security operations center (SOC).

Your role is to investigate security incidents by gathering evidence and recommending appropriate responses.
You have access to read-only investigation tools that query a simulated security dataset.

 Investigation workflow:
1. Analyze the incident details provided
2. Use the investigation tools to gather evidence
3. Evaluate the evidence and determine if more investigation is needed
4. Either conclude with a finding and recommended action, or request human review if ambiguous

Rules:
- Only use the provided investigation tools - no assumptions about real systems
- Be thorough but efficient - don't re-investigate the same angle
- If evidence is conclusive, use conclude_investigation
- If evidence is ambiguous, use request_human_review
- Always explain your reasoning
- Remember: all data is simulated for demonstration purposes

Available tools:
- inspect_login_history: Look up recent login attempts for a user
- inspect_ip_reputation: Check IP address reputation (clean/suspicious/malicious)
- inspect_privilege_changes: Review privilege and permission changes
- inspect_related_incidents: Find other incidents involving the same user
- inspect_asset_context: Look up devices associated with a user
- conclude_investigation: Conclude with finding and recommended action
- request_human_review: Request human analyst review
"""

# Demo mode - agent acts without asking, good for recordings
EAGER_PROMPT = SYSTEM_PROMPT + "\n\nAct immediately and autonomously. When you have enough evidence, conclude the investigation. If uncertain, request human review."


class SentinelX:
    """Sentinel X - AI Cyber Incident Commander.
    
    Uses Strands Decider 2B for investigation tool selection (#tool-selection pattern),
    paired with Amazon Bedrock for generative responses.
    """

    def __init__(
        self,
        decider: Decider | None = None,
        model_id: str | None = None,
        eager: bool = False,
        max_investigation_steps: int = 5,
    ):
        import os
        
        self.decider = decider or Decider()
        self.eager = eager or os.environ.get("DEMO_EAGER") == "1"
        self.model_id = model_id or default_model_id()
        self.max_investigation_steps = max_investigation_steps
        self.sessions: dict[str, tuple[Agent, IncidentInvestigator]] = {}

    def _session(self, session_id: str) -> tuple[Agent, IncidentInvestigator]:
        if session_id not in self.sessions:
            investigator = IncidentInvestigator(
                self.decider,
                threshold=0.6,
                max_steps=self.max_investigation_steps,
            )
            agent = Agent(
                model=agent_model(self.model_id),
                system_prompt=EAGER_PROMPT if self.eager else SYSTEM_PROMPT,
                tools=TOOLS,
                interventions=[investigator],
                callback_handler=None,
            )
            self.sessions[session_id] = (agent, investigator)
        return self.sessions[session_id]

    def analyze_incident(
        self,
        incident: dict[str, Any],
        session_id: str = "default",
    ) -> dict[str, Any]:
        """Analyze a security incident and return a structured incident report.
        
        Args:
            incident: Dictionary with incident details (id, type, user, severity, description)
            session_id: Optional session ID for conversation continuity
            
        Returns:
            Dictionary with incident_id, category, severity, decision, confidence,
            evidence, investigation_steps, explanation, recommended_actions,
            requires_human_review, simulated_data
        """
        agent, investigator = self._session(session_id)
        
        # Set the incident context for the investigator
        investigator.set_incident(incident)
        
        # Build the investigation prompt
        incident_id = incident.get("incident_id", f"INC-{time.time()}")
        prompt = f"""Investigate this security incident and recommend an appropriate response.

INCIDENT DETAILS:
- ID: {incident_id}
- Type: {incident.get('type', 'unknown')}
- Severity: {incident.get('severity', 'medium')}
- User: {incident.get('user', 'unknown')}
- Description: {incident.get('description', 'No description provided')}

Please investigate this incident by gathering relevant evidence using the available tools.
After gathering evidence, either:
1. Conclude the investigation with a finding and recommended action, OR
2. Request human review if the case is ambiguous

All data is simulated for demonstration. Pro with the investigation."""

        t0 = time.perf_counter()
        
        try:
            result = agent(prompt)
            reply = strip_thinking(str(result))
        except Exception as e:
            reply = f"Error during investigation: {str(e)}"
        
        latency_ms = round((time.perf_counter() - t0) * 0)
        
        # Build the structured incident report
        investigation_steps = []
        for i, step in enumerate(investigator.investigation_log, 1):
            investigation_steps.append({
                "step": i,
                "tool": step.get("tool", "unknown"),
                "confidence": step.get("confidence"),
                "verdict": step.get("verdict", "proceed"),
                "result": step.get("result", "")[:200],
            })
        
        # Determine if human review is needed based on investigation log
        requires_human_review = any(
            step.get("tool") == "request_human_review" 
            for step in investigator.investigation_log
        )
        
        # Check for max steps reached
        if investigator.step_count >= investigator.max_steps and not requires_human_review:
            requires_human_review = True
            reply += "\n\n[Note: Investigation reached maximum step limit. Human review recommended.]"
        
        # Extract confidence from decider decisions
        confidences = [
            step.get("confidence", 0) 
            for step in investigation_steps 
            if step.get("confidence")
        ]
        confidence = sum(confidences) / len(confidences) if confidences else None
        
        return {
            "incident_id": incident_id,
            "category": incident.get("type", "unknown"),
            "severity": incident.get("severity", "medium"),
            "decision": investigator.investigation_log[-1].get("tool", "unknown") if investigator.investigation_log else "pending",
            "confidence": round(confidence, 3) if confidence else None,
            "evidence": [step.get("result", "") for step in investigation_steps if step.get("result")],
            "investigation_steps": investigation_steps,
            "explanation": reply,
            "recommended_actions": self._extract_recommended_actions(investigator.investigation_log),
            "requires_human_review": requires_human_review,
            "simulated_data": True,
            "model_id": self.model_id,
            "latency_ms": latency_ms,
            "pattern_tag": PATTERN_TAG,
        }

    def _extract_recommended_actions(self, investigation_log: list[dict]) -> list[str]:
        """Extract recommended actions from the investigation log."""
        actions = []
        for step in investigation_log:
            tool = step.get("tool", "")
            if tool == "conclude_investigation":
                result = step.get("result", "")
                if result:
                    actions.append(f"Concluded: {result[:100]}")
            elif tool == "request_human_review":
                actions.append("Human review requested")
            elif tool in ("inspect_login_history", "inspect_ip_reputation", 
                         "inspect_privilege_changes", "inspect_related_incidents", 
                         "inspect_asset_context"):
                actions.append(f"Investigated via {tool}")
        
        return actions if actions else ["Investigation in progress"]

    def chat(self, message: str, session_id: str = "default", images: list[Any] | None = None) -> dict[str, Any]:
        """Chat with Sentinel X about security operations.
        
        This allows interactive investigation through the chat interface.
        The images parameter is accepted for compatibility but not used in this security agent.
        """
        agent, investigator = self._session(session_id)
        
        t0 = time.perf_counter()
        result = agent(message)
        reply = strip_thinking(str(result))
        
        return {
            "reply": reply,
            "decisions": investigator.investigation_log,
            "model_id": self.model_id,
            "latency_ms": round((time.perf_counter() - t0) * 1000),
            "agent": NAME,
        }


# Alias for compatibility with the kit's expected interface
HackathonAgent = SentinelX


if __name__ == "__main__":
    import sys
    
    # Demo: analyze a sample incident
    incidents = [
        {
            "incident_id": "INC-2026-001",
            "type": "failed_login",
            "user": "user_001",
            "severity": "medium",
            "description": "Multiple failed login attempts followed by successful login from unusual location (London UK, from San Francisco IP)"
        },
        {
            "incident_id": "INC-2026-002",
            "type": "privilege_escalation",
            "user": "user_001",
            "severity": "high",
            "description": "Unusual privilege escalation - user granted admin role immediately after suspicious login"
        },
    ]
    
    agent = SentinelX(eager=True)
    for incident in incidents:
        print(f"\n{'='*60}")
        print(f"Analyzing: {incident['incident_id']}")
        print(f"{'='*60}")
        result = agent.analyze_incident(incident)
        print(json.dumps(result, indent=2, default=str))