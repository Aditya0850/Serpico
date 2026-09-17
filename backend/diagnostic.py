# Diagnostic script to see current system behavior
# Imports: asyncio, sys, os
# Affected API: None (diagnostic only)
# Data schemas: Evidence, InvestigationResult, etc.
# User's verbatim instruction: Create diagnostic script to understand current system behavior for test adjustment.

import asyncio
import sys
import os
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

async def run_investigation(test_content: str, test_type: str = "text"):
    text_content = extract_text_from_content(test_content, test_type)
    extracted_evidence = extract_evidence(test_content, test_type)

    evidence_agent = EvidenceAgent()
    social_engineering_agent = SocialEngineeringAgent()
    threat_intelligence_agent = ThreatIntelligenceAgent()
    devils_advocate_agent = DevilsAdvocateAgent()
    judge_agent = JudgeAgent()

    evidence_task = asyncio.create_task(evidence_agent.analyze(text_content))
    social_task = asyncio.create_task(social_engineering_agent.analyze(text_content))
    threat_task = asyncio.create_task(threat_intelligence_agent.analyze(text_content))

    evidence_result, social_result, threat_result = await asyncio.gather(
        evidence_task, social_task, threat_task
    )

    devils_advocate_result = await devils_advocate_agent.analyze(
        evidence_result, social_result, threat_result
    )

    verdict = await judge_agent.analyze(
        evidence_content=text_content,
        evidence_type=test_type,
        evidence_result=evidence_result,
        social_engineering_result=social_result,
        threat_intelligence_result=threat_result,
        devils_advocate_result=devils_advocate_result
    )

    case_id = f"TRC-{str(uuid.uuid4())[:8].upper()}"

    from models.investigation import InvestigationResult
    result = InvestigationResult(
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

    return result

async def main():
    test_cases = [
        ("Obvious Phishing", "URGENT: Your PayPal account has been locked! Click http://paypa1.com-security.net/verify to unlock it now or lose access forever."),
        ("Benign Message", "Hello, just wanted to say thanks for the meeting yesterday. Let me know if you need anything else."),
        ("Suspicious URL", "Please review the attached document at http://bit.ly/suspicious-link for more details."),
        ("Urgency + Credential Request", "IMMEDIATE ACTION REQUIRED: Your bank account will be closed! Provide your SSN and password at http://secure-bank-update.com to avoid closure."),
        ("Authority Impersonation", "This is Officer Johnson from the FBI. Your computer has been involved in illegal activities. Visit http://fbi-security-alert.com to provide information to avoid arrest."),
        ("Ambiguous Evidence", "Hey, check out this interesting article I found: https://example.com/news/tech-update"),
    ]

    for name, content in test_cases:
        print(f"\n{name}:")
        print(f"Content: {content}")
        result = await run_investigation(content)
        print(f"Risk Level: {result.verdict.risk_level}")
        print(f"Confidence: {result.verdict.confidence}")
        print(f"Reasoning: {', '.join(result.verdict.reasoning)}")
        print("-" * 50)

if __name__ == "__main__":
    asyncio.run(main())