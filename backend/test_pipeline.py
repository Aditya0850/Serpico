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

async def test_pipeline():
    """Test the complete investigation pipeline"""
    print("Testing TRACE investigation pipeline...")

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

    # Test Evidence model
    print("\nTesting Evidence model...")
    evidence_model = Evidence(
        type=test_type,
        content=test_content
    )
    print(f"Evidence model created: {evidence_model.type}")

    print("\nPipeline test completed successfully!")
    return True

if __name__ == "__main__":
    try:
        asyncio.run(test_pipeline())
    except Exception as e:
        print(f"Error during pipeline test: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)