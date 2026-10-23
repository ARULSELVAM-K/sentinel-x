"""Tests for Sentinel X investigation logic and decision patterns."""

import pytest
from unittest.mock import MagicMock, patch

from agent.decision import IncidentInvestigator, QUESTIONS, TOOL_OPTIONS
from decider_kit import Decider


class FakeDecision:
    """Fake decision for testing."""
    def __init__(self, label="inspect_login_history", confidence=0.8, probabilities=None):
        self.label = label
        self.confidence = confidence
        self.probabilities = probabilities or {label: confidence}


class FakeDecider:
    """Fake decider for testing."""
    def __init__(self, decision=None):
        self.decision = decision or FakeDecision()
        self.last_latency_ms = 100
    
    def ask(self, state, questions):
        return {"action": self.decision}


def test_investigation_tools_always_allowed():
    """Test that investigation tools are always allowed to proceed."""
    decider = FakeDecider()
    investigator = IncidentInvestigator(decider, threshold=0.6, max_steps=5)
    investigator.set_incident({
        "incident_id": "TEST-001",
        "type": "failed_login",
        "user": "user_001",
        "severity": "medium",
        "description": "Test incident"
    })
    
    # Create a mock event for each investigation tool
    for tool_name in ["inspect_login_history", "inspect_ip_reputation", 
                     "inspect_privilege_changes", "inspect_related_incidents",
                     "inspect_asset_context"]:
        mock_event = MagicMock()
        mock_event.tool_use = {"name": tool_name, "input": {"user_id": "user_001"}}
        
        result = investigator.before_tool_call(mock_event)
        
        # Should always proceed for investigation tools
        from strands.interventions import Proceed
        assert isinstance(result, Proceed), f"Investigation tool {tool_name} should be allowed"


def test_conclude_requires_evidence():
    """Test that conclude_investigation requires evidence."""
    decider = FakeDecider()
    investigator = IncidentInvestigator(decider, threshold=0.6, max_steps=5)
    investigator.set_incident({
        "incident_id": "TEST-001",
        "type": "failed_login",
        "user": "user_001",
        "severity": "medium",
        "description": "Test incident"
    })
    
    # Try to conclude without evidence
    mock_event = MagicMock()
    mock_event.tool_use = {"name": "conclude_investigation", "input": {"finding": "test"}}
    
    result = investigator.before_tool_call(mock_event)
    
    # Should be redirected (guided) to gather evidence first
    from strands.interventions import Guide
    assert isinstance(result, Guide), "Should guide to gather evidence first"
    
    # Check that the investigation log shows redirect
    assert any(step.get("verdict") == "redirect" for step in investigator.investigation_log)


def test_human_review_requires_evidence():
    """Test that request_human_review requires evidence."""
    decider = FakeDecider()
    investigator = IncidentInvestigator(decider, threshold=0.6, max_steps=5)
    investigator.set_incident({
        "incident_id": "TEST-001",
        "type": "failed_login",
        "user": "user_001",
        "severity": "medium",
        "description": "Test incident"
    })
    
    # Try to request review without evidence
    mock_event = MagicMock()
    mock_event.tool_use = {"name": "request_human_review", "input": {"reason": "test"}}
    
    result = investigator.before_tool_call(mock_event)
    
    # Should be redirected to gather evidence first
    from strands.interventions import Guide
    assert isinstance(result, Guide), "Should guide to gather evidence first"


def test_conclude_allowed_with_evidence():
    """Test that conclude_investigation is allowed with evidence."""
    decider = FakeDecider()
    investigator = IncidentInvestigator(decider, threshold=0.6, max_steps=5)
    investigator.set_incident({
        "incident_id": "TEST-001",
        "type": "failed_login",
        "user": "user_001",
        "severity": "medium",
        "description": "Test incident"
    })
    
    # Add evidence first
    investigator.investigation_log.append({
        "tool": "inspect_login_history",
        "result": "Found suspicious login pattern",
        "verdict": "proceed"
    })
    
    # Now try to conclude
    mock_event = MagicMock()
    mock_event.tool_use = {"name": "conclude_investigation", "input": {"finding": "test"}}
    
    result = investigator.before_tool_call(mock_event)
    
    # Should proceed
    from strands.interventions import Proceed
    assert isinstance(result, Proceed), "Should allow conclusion with evidence"


def test_investigation_audit_log():
    """Test that investigation steps are properly logged."""
    decider = FakeDecider()
    investigator = IncidentInvestigator(decider, threshold=0.6, max_steps=5)
    investigator.set_incident({
        "incident_id": "TEST-001",
        "type": "failed_login",
        "user": "user_001",
        "severity": "medium",
        "description": "Test incident"
    })
    
    # Call an investigation tool
    mock_event = MagicMock()
    mock_event.tool_use = {"name": "inspect_login_history", "input": {"user_id": "user_001"}}
    
    investigator.before_tool_call(mock_event)
    
    # Check log
    assert len(investigator.investigation_log) == 1
    assert investigator.investigation_log[0]["tool"] == "inspect_login_history"
    assert investigator.investigation_log[0]["verdict"] == "proceed"


def test_questions_have_all_tools():
    """Test that QUESTIONS includes all required investigation tools."""
    action_question = QUESTIONS["action"]
    assert action_question["type"] == "choice"
    
    # Check all required tools are in options
    criteria = action_question.get("criteria", {})
    required_tools = [
        "inspect_login_history", "inspect_ip_reputation",
        "inspect_privilege_changes", "inspect_related_incidents",
        "inspect_asset_context", "conclude_investigation", "request_human_review"
    ]
    
    for tool in required_tools:
        assert tool in criteria, f"{tool} should be in decision options"


def test_build_state_includes_evidence():
    """Test that _build_state includes evidence from investigation log."""
    decider = FakeDecider()
    investigator = IncidentInvestigator(decider, threshold=0.6, max_steps=5)
    investigator.set_incident({
        "incident_id": "TEST-001",
        "type": "failed_login",
        "user": "user_001",
        "severity": "medium",
        "description": "Test incident"
    })
    
    # Add evidence
    investigator.investigation_log.append({
        "tool": "inspect_login_history",
        "result": "Found failed logins from 203.0.113.42",
        "verdict": "proceed"
    })
    
    state = investigator._build_state()
    
    assert "TEST-001" in state
    assert "failed_login" in state
    assert "EVIDENCE GATHERED" in state
    assert "LOGIN HISTORY" in state or "inspect_login_history" in state


def test_max_steps_tracking():
    """Test that step count is properly tracked."""
    decider = FakeDecider()
    investigator = IncidentInvestigator(decider, threshold=0.6, max_steps=3)
    investigator.set_incident({
        "incident_id": "TEST-001",
        "type": "failed_login",
        "user": "user_001",
        "severity": "medium",
        "description": "Test incident"
    })
    
    assert investigator.step_count == 0
    
    # Add evidence
    investigator.investigation_log.append({"tool": "inspect_login_history", "verdict": "proceed"})
    investigator.step_count += 1
    
    assert investigator.step_count == 1
    assert investigator.max_steps == 3