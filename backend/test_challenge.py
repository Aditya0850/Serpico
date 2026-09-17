# Test for Attack This Verdict endpoint
# Importers/callers: EvidenceAgent, SocialEngineeringAgent, ThreatIntelligenceAgent, DevilsAdvocateAgent, JudgeAgent, Evidence model
# Affected API: POST /investigate/{case_id}/challenge in main.py
# Data schemas: Evidence, InvestigationResult, Verdict, and the agent result dictionaries
# User's verbatim instruction: Implement the Attack This Verdict endpoint (POST /investigate/{case_id}/challenge) as per the instructions.

import asyncio
import sys
import os

# Add the backend directory to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from models.investigation import Evidence
from agents.evidence_agent import EvidenceAgent
from agents.social_engineering_agent import SocialEngineeringAgent
from agents.threat_intelligence_agent import ThreatIntelligenceAgent
from agents.devils_advocate_agent import DevilsAdvocateAgent
from agents.judge_agent import JudgeAgent
from utils.evidence_extraction import extract_evidence, extract_text_from_content
import uuid
from datetime import datetime

async def test_challenge_endpoint():
    """Test the Attack This Verdict functionality"""
    print("Testing TRACE Attack This Verdict endpoint...")

    # Test evidence
    test_content = "URGENT: Your account will be suspended! Click http://paypa1.com-security.net to verify your information immediately or lose access forever. This is a final notice from authority."
    test_type = "text"

    print(f"Test content: {test_content}")

    # Extract text
    text_content = extract_text_from_content(test_content, test_type)
    print(f"Extracted text: {text_content}")

    # Extract evidence
    extracted_evidence = extract_evidence(test_content, test_type)
    print(f"Extracted evidence URLs: {extracted_evidence.urls}")
    print(f"Extracted evidence entities: {extracted_evidence.entities}")
    print(f"Extracted evidence indicators: {extracted_evidence.indicators}")

    # Initialize agents
    evidence_agent = EvidenceAgent()
    social_engineering_agent = SocialEngineeringAgent()
    threat_intelligence_agent = ThreatIntelligenceAgent()
    devils_advocate_agent = DevilsAdvocateAgent()
    judge_agent = JudgeAgent()

    # Run agents in parallel
    print("\nRunning agent analyses...")
    evidence_task = asyncio.create_task(evidence_agent.analyze(text_content))
    social_task = asyncio.create_task(social_engineering_agent.analyze(text_content))
    threat_task = asyncio.create_task(threat_intelligence_agent.analyze(text_content))

    evidence_result, social_result, threat_result = await asyncio.gather(
        evidence_task, social_task, threat_task
    )

    print(f"Evidence agent findings: {len(evidence_result.get('findings', []))}")
    print(f"Social engineering agent findings: {len(social_result.get('findings', []))}")
    print(f"Threat intelligence agent findings: {len(threat_result.get('findings', []))}")

    # Run Devil's Advocate
    print("\nRunning Devil's Advocate analysis...")
    devils_advocate_result = await devils_advocate_agent.analyze(
        evidence_result, social_result, threat_result
    )
    print(f"Devil's Advocate challenges: {len(devils_advocate_result.get('challenges', []))}")
    print(f"Devil's Advocate counter-evidence: {len(devils_advocate_result.get('counter_evidence', []))}")

    # Run Judge
    print("\nRunning Judge analysis...")
    verdict = await judge_agent.analyze(
        evidence_content=text_content,
        evidence_type=test_type,
        evidence_result=evidence_result,
        social_engineering_result=social_result,
        threat_intelligence_result=threat_result,
        devils_advocate_result=devils_advocate_result
    )

    print(f"Verdict risk level: {verdict.risk_level}")
    print(f"Verdict confidence: {verdict.confidence}")
    print(f"Verdict reasoning: {verdict.reasoning}")
    print(f"Verdict recommended actions: {verdict.recommended_actions}")

    # Create a case ID and store the investigation (simulating what the API does)
    case_id = f"TRC-{str(uuid.uuid4())[:8].upper()}"
    print(f"\nCreated case ID: {case_id}")

    # Simulate storing the investigation (as done in main.py)
    from models.investigation import InvestigationResult

    investigation_result = InvestigationResult(
        case_id=case_id,
        evidence=Evidence(type=test_type, content=test_content),
        extracted_evidence=extracted_evidence,
        agents={
            "evidence": evidence_result,
            "social_engineering": social_result,
            "threat_intelligence": threat_result
        },
        devils_advocate=devils_advocate_result,
        verdict=verdict,
        timestamp=datetime.utcnow().isoformat() + "Z"
    )

    # Now test the challenge functionality
    print("\n=== Testing Attack This Verdict ===")

    # Re-run Devil's Advocate to generate NEW challenges
    devils_advocate_agent2 = DevilsAdvocateAgent()
    new_challenges_result = await devils_advocate_agent2.analyze(
        investigation_result.agents["evidence"],
        investigation_result.agents["social_engineering"],
        investigation_result.agents["threat_intelligence"]
    )
    print(f"New challenges generated: {len(new_challenges_result.get('challenges', []))}")

    # Run Judge again with the new challenges to get a revised verdict
    judge_agent2 = JudgeAgent()
    revised_verdict = await judge_agent2.analyze(
        evidence_content=investigation_result.evidence.content,
        evidence_type=investigation_result.evidence.type,
        evidence_result=investigation_result.agents["evidence"],
        social_engineering_result=investigation_result.agents["social_engineering"],
        threat_intelligence_result=investigation_result.agents["threat_intelligence"],
        devils_advocate_result=new_challenges_result
    )

    print(f"Revised verdict risk level: {revised_verdict.risk_level}")
    print(f"Revised verdict confidence: {revised_verdict.confidence}")
    print(f"Revised verdict reasoning: {revised_verdict.reasoning}")

    # Determine what changed between the verdicts
    what_changed = []
    if investigation_result.verdict.risk_level != revised_verdict.risk_level:
        what_changed.append(f"Risk level changed from {investigation_result.verdict.risk_level} to {revised_verdict.risk_level}")

    if abs(investigation_result.verdict.confidence - revised_verdict.confidence) > 0.1:
        what_changed.append(f"Confidence changed from {investigation_result.verdict.confidence:.2f} to {revised_verdict.confidence:.2f}")

    print(f"What changed: {what_changed if what_changed else ['No significant changes in verdict']}")

    print("\nAttack This Verdict test completed successfully!")
    return True

if __name__ == "__main__":
    try:
        asyncio.run(test_challenge_endpoint())
    except Exception as e:
        print(f"Error during challenge test: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)