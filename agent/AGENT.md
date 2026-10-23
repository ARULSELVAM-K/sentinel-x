# Sentinel X - AI Cyber Incident Commander

## Use Case Overview

Sentinel X is an AI-powered Cyber Incident Commander that investigates simulated security incidents and recommends safe responses. It demonstrates how Strands Decider 2B can be used for tool selection in a security operations context.

## Problem It Solves

Security Operations Centers (SOCs) face alert fatigue with thousands of security events daily. Analysts must manually investigate each alert, deciding which tools to use and when to escalate. This is slow, inconsistent, and doesn't scale.

## How It Works

1. **Incident Intake**: Accepts security alerts with incident type, user, severity, and description
2. **Investigation**: Uses Strands Decider 2B to select the most appropriate investigation tool based on context
3. **Evidence Gathering**: Invokes read-only investigation tools against a simulated security dataset
4. **Decision**: Concludes with a finding and recommended action, or escalates to human review when ambiguous
5. **Reporting**: Returns a structured incident report with audit trail

## Strands Decider 2B Role

The decider selects which investigation action to take next:
- `inspect_login_history` - Check user's login patterns
- `inspect_ip_reputation` - Assess IP threat intelligence
- `inspect_privilege_changes` - Review permission modifications
- `inspect_related_incidents` - Find related security events
- `inspect_asset_context` - Verify device trust
- `conclude_investigation` - Finish with finding
- `request_human_review` - Escalate ambiguous cases

This is the **#tool-selection** decision pattern.

## Demo Scenarios Included

1. **Repeated failed logins** - user_001: Multiple failures then success from unusual location
2. **Suspicious privilege change** - user_001: Admin role granted after suspicious login
3. **Benign pattern** - user_003: Normal login from known location (should NOT escalate)
4. **Related incidents** - user_002: Multiple alerts potentially linked
5. **Ambiguous case** - Requires human review due to insufficient evidence

## Architecture

- **Decision**: Strands Decider 2B (#tool-selection)
- **Generative**: Amazon Bedrock (Nova by default)
- **Tools**: Read-only security investigation (simulated data)
- **Pattern**: Tool selection with confidence threshold and max steps

## Built with

Built with the AWS User Group Madurai Strands Decider hackathon kit