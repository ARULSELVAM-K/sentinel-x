"""REUSABLE DECISION PATTERN: security investigation tool selection  (#tool-selection)

Sentinel X uses Strands Decider 2B to select the next investigation action based on
the security incident context. This replaces LLM-based tool selection with a fast,
calibrated decision that can be audited.

What it does
    Given a security incident (alert type, user, evidence so far), Strands Decider 2B
    selects the most appropriate investigation tool from the available options.
    It considers:
    - The incident type and severity
    - What evidence has already been collected
    - Which tool provides the most useful next piece of information
    
    The decider can also decide to conclude the investigation or request human review
    when the evidence is sufficient or ambiguous.

Typed questions and options
    action (choice): which investigation action to take next, based on tool descriptions.
    See QUESTIONS below.

Wiring
    `IncidentInvestigator` is a Strands InterventionHandler that intercepts before each
    tool call. It builds the state from the current incident context and asks the decider
    which action to take. If the LLM tries to call a different tool, it's guided back.

How to reuse it
    Copy this pattern for any tool-selection use case. Change TOOL_OPTIONS to describe
    your available tools, and reword the question for your domain. The threshold controls
    when the decider's choice is followed vs. when the LLM decides.
"""

from __future__ import annotations

import json
from typing import Any

from strands.interventions import Confirm, Deny, Guide, InterventionHandler, Proceed

from decider_kit import Decider
from decider_kit.patterns.tool_selection import _describe

IS_KIT_EXAMPLE = False  # This is Sentinel X, not the kit example

PATTERN_TAG = "#tool-selection"

# Investigation tool options - the decider chooses which to invoke
# Each tool has a one-line description that serves as its option text
TOOL_OPTIONS = {
    "inspect_login_history": "Look up recent login attempts for a user (timestamp, IP, location, status)",
    "inspect_ip_reputation": "Check IP address reputation and threat intelligence (clean/suspicious/malicious)",
    "inspect_privilege_changes": "Review privilege and permission changes for a user",
    "inspect_related_incidents": "Find other security incidents involving the same user",
    "inspect_asset_context": "Look up devices and assets associated with a user",
    "conclude_investigation": "Conclude the investigation with a finding and recommended action",
    "request_human_review": "Request human analyst review for an ambiguous case",
}

QUESTIONS = {
    "action": Decider.choice(
        "Given this security incident and evidence gathered so far, which investigation action "
        "would provide the most useful next piece of information? Choose 'conclude_investigation' "
        "when you have enough evidence, or 'request_human_review' when the case is ambiguous.",
        TOOL_OPTIONS
    ),
}


class IncidentInvestigator(InterventionHandler):
    """Security incident investigation coordinator using Strands Decider 2B.
    
    Intercepts tool calls and uses the decider to select the appropriate investigation action.
    Tracks the investigation state and ensures each step is properly reasoned.
    """

    name = "incident-investigator"

    def __init__(
        self,
        decider: Decider,
        threshold: float = 0.6,
        max_steps: int = 5,
        # Current incident context - set by the agent
        incident_context: dict[str, Any] | None = None,
    ):
        self.decider = decider
        self.threshold = threshold
        self.max_steps = max_steps
        self.incident_context = incident_context or {}
        self.investigation_log: list[dict[str, Any]] = []
        self.step_count = 0

    def set_incident(self, incident: dict[str, Any]) -> None:
        """Set the current incident being investigated."""
        self.incident_context = incident
        self.investigation_log = []
        self.step_count = 0

    def _build_state(self, event: Any = None) -> str:
        """Build the state text for the decider from current context."""
        parts = []
        
        # Incident information
        incident = self.incident_context
        parts.append(f"INCIDENT: {incident.get('incident_id', 'unknown')}")
        parts.append(f"Type: {incident.get('type', 'unknown')}")
        parts.append(f"Severity: {incident.get('severity', 'unknown')}")
        parts.append(f"User: {incident.get('user', 'unknown')}")
        parts.append(f"Description: {incident.get('description', 'No description')}")
        
        # Evidence gathered so far - include actual data from tool results
        if self.investigation_log:
            parts.append("\nEVIDENCE GATHERED:")
            for i, step in enumerate(self.investigation_log, 1):
                tool = step.get("tool", "unknown")
                result = step.get("result", "")
                verdict = step.get("verdict", "")
                
                # Summarize based on tool type
                if tool == "inspect_login_history" and result:
                    parts.append(f"{i}. LOGIN HISTORY: {result[:300]}")
                elif tool == "inspect_ip_reputation" and result:
                    parts.append(f"{i}. IP REPUTATION: {result[:300]}")
                elif tool == "inspect_privilege_changes" and result:
                    parts.append(f"{i}. PRIVILEGE CHANGES: {result[:300]}")
                elif tool == "inspect_related_incidents" and result:
                    parts.append(f"{i}. RELATED INCIDENTS: {result[:300]}")
                elif tool == "inspect_asset_context" and result:
                    parts.append(f"{i}. ASSET CONTEXT: {result[:300]}")
                else:
                    parts.append(f"{i}. {tool}: {str(result)[:200]}")
        
        # Steps taken and remaining
        parts.append(f"\nInvestigation progress: {self.step_count}/{self.max_steps} steps used")
        
        # Guidance for the decider
        if self.step_count >= self.max_steps:
            parts.append("WARNING: Max investigation steps reached. Either conclude or request human review.")
        elif self.step_count >= 2:
            parts.append("GUIDANCE: You have gathered evidence. If suspicious patterns are found, conclude with findings. If uncertain, request human review.")
        
        return "\n".join(parts)

    def _log_decision(self, decision: dict[str, Any]) -> None:
        """Log a decision for the audit trail."""
        self.investigation_log.append(decision)
        self.step_count += 1

    def before_invocation(self, event, **kwargs):
        """Before processing a new user message, check if we've hit the step limit."""
        if self.step_count >= self.max_steps:
            # Force conclusion when max steps reached
            self.investigation_log.append({
                "tool": "max_steps_reached",
                "result": "Investigation step limit reached",
                "action": "force_conclude"
            })
        return Proceed()

    def before_tool_call(self, event, **kwargs):
        """Before each tool call, validate it's the right tool for the current investigation stage.
        
        The decider selects the next action. If the LLM tries to conclude or request review
        too early (without evidence), redirect to gather evidence first.
        """
        name = event.tool_use["name"]
        args = event.tool_use.get("input") or {}
        
        # Get the user_id from args for this investigation
        user_id = args.get("user_id") or self.incident_context.get("user", "unknown")
        
        # Track what evidence we've collected
        evidence_collected = set()
        for step in self.investigation_log:
            tool = step.get("tool", "")
            if tool.startswith("inspect_"):
                evidence_collected.add(tool)
        
        # Investigation tools that should always be allowed
        investigation_tools = {
            "inspect_login_history", "inspect_ip_reputation", 
            "inspect_privilege_changes", "inspect_related_incidents", 
            "inspect_asset_context"
        }
        
        # If LLM is calling an investigation tool, always allow it
        if name in investigation_tools:
            # Log this investigation tool call
            self._log_decision({
                "tool": name,
                "args": args,
                "verdict": "proceed",
                "reason": "investigation_tool_allowed",
            })
            return Proceed()
        
        # For conclude_investigation or request_human_review, check if we have evidence
        if name in ("conclude_investigation", "request_human_review"):
            # Require at least one piece of evidence before concluding/escalating
            if len(self.investigation_log) < 1:
                # No evidence gathered yet - guide to investigate first
                self._log_decision({
                    "tool": name,
                    "args": args,
                    "verdict": "redirect",
                    "reason": "no_evidence_gathered",
                    "redirect_to": "inspect_login_history",
                })
                return Guide(feedback="Gather evidence first. Start by inspecting the login history using inspect_login_history.")
            
            # Check for redundant evidence (same tool called twice)
            if name in evidence_collected:
                self._log_decision({
                    "tool": name,
                    "args": args,
                    "verdict": "redirect",
                    "reason": "redundant_action",
                    "redirect_to": "conclude_investigation",
                })
                return Guide(feedback="You've already gathered evidence. Conclude the investigation now.")
            
            # We have evidence - allow conclusion or escalation
            self._log_decision({
                "tool": name,
                "args": args,
                "verdict": "proceed",
                "reason": "evidence_available",
            })
            return Proceed()
        
        # Build state for the decider to decide on unknown tool
        state = self._build_state(event)
        
        # Ask the decider which action to take for unknown tools
        try:
            result = self.decider.ask(state, QUESTIONS)
            decision = result.get("action")
        except Exception as e:
            # If decider fails, allow the tool call (fail open for safety)
            self.investigation_log.append({
                "tool": name,
                "args": args,
                "verdict": "proceed",
                "reason": f"decider_error: {str(e)[:100]}"
            })
            return Proceed()

        if decision is None:
            return Proceed()

        selected_tool = decision.label
        confidence = decision.confidence
        
        # Log this decision
        self._log_decision({
            "tool": selected_tool,
            "confidence": confidence,
            "probabilities": decision.probabilities,
            "llm_requested": name,
            "args": args,
        })

        # Check if the LLM is calling the right tool
        if name != selected_tool:
            # The LLM is calling a different tool than what the decider selected
            if confidence >= self.threshold:
                # High confidence - redirect to the correct tool
                if selected_tool == "conclude_investigation":
                    return Guide(feedback="You have gathered enough evidence. Conclude the investigation now using conclude_investigation.")
                elif selected_tool == "request_human_review":
                    return Guide(feedback="This case is ambiguous. Request human review now using request_human_review.")
                else:
                    return Guide(feedback=f"The most useful next step is {selected_tool}. Call that tool instead.")
            else:
                # Low confidence - let the LLM proceed but log the disagreement
                self.investigation_log[-1]["verdict"] = "llm_disagreement"
                return Proceed()

        # The LLM called the right tool - proceed but log it
        self.investigation_log[-1]["verdict"] = "proceed"
        return Proceed()

    def after_tool_call(self, event, **kwargs):
        """After each tool call, store the result for context."""
        name = event.tool_use["name"]
        args = event.tool_use.get("input") or {}
        
        # Find the most recent log entry for this tool call and add the result
        for entry in reversed(self.investigation_log):
            if entry.get("tool") == name:
                # Try to get result from event
                result = kwargs.get("result") or {}
                entry["result"] = str(result)[:500] if result else "completed"
                break
        
        return Proceed()


# Standalone function to get investigation recommendation
def get_investigation_action(incident: dict[str, Any], decider: Decider) -> dict[str, Any]:
    """Get the recommended investigation action for an incident.
    
    This can be called directly without going through the Strands agent,
    useful for batch processing or initial triage.
    """
    investigator = IncidentInvestigator(decider)
    investigator.set_incident(incident)
    
    state = investigator._build_state()
    result = decider.ask(state, QUESTIONS)
    decision = result.get("action")
    
    if decision:
        return {
            "action": decision.label,
            "confidence": decision.confidence,
            "probabilities": decision.probabilities,
        }
    return {"action": "inspect_login_history", "confidence": 0.5, "probabilities": {}}