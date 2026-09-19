from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import uuid
from datetime import datetime
import asyncio
import logging

# Import our models and agents
from models.investigation import Evidence, ExtractedEvidence, InvestigationResult, Verdict, DevilsAdvocateResult
from agents.evidence_agent import EvidenceAgent
from agents.social_engineering_agent import SocialEngineeringAgent
from agents.threat_intelligence_agent import ThreatIntelligenceAgent
from agents.devils_advocate_agent import DevilsAdvocateAgent
from agents.judge_agent import JudgeAgent
from s3_storage import store_evidence
from dynamodb_storage import store_investigation, get_investigation

import os

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="TRACE API", version="0.1.0")

# Investigation persistence layer
# - When DynamoDB is configured: use DynamoDB exclusively
# - When DynamoDB is NOT configured:
#     * If ENV=development: use in-memory storage with warning (local development mode)
#     * If ENV!=development: fail clearly (production safety)

# Storage mode detection
is_development_mode = os.getenv("ENV", "").lower() == "development"
is_dynamodb_configured = aws_config.is_dynamodb_configured()

# In-memory storage for local development fallback
_investigation_store = {}

def get_persistence_layer():
    """Returns the appropriate storage layer based on configuration."""
    if is_dynamodb_configured:
        # Use DynamoDB when configured (ignores development mode for safety)
        return "dynamodb"
    elif is_development_mode:
        # Use in-memory storage only in explicit development mode
        logger.warning(
            "RUNNING IN LOCAL DEVELOPMENT MODE: Investigation data is stored in memory "
            "and will be lost on application restart. Do not use in production."
        )
        return "memory"
    else:
        # Production mode without DynamoDB configured - fail fast
        error_msg = (
            "DynamoDB is not configured and ENV is not set to 'development'. "
            "Set ENV=development for local development with in-memory storage, "
            "or configure DynamoDB for production use."
        )
        logger.error(error_msg)
        raise RuntimeError(error_msg)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, replace with specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def root():
    return {"message": "TRACE API is running"}

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

@app.post("/investigate", response_model=InvestigationResult)
async def investigate_evidence(evidence: Evidence):
    """
    Real investigation endpoint that uses the agent pipeline to analyze evidence.
    """
    case_id = f"TRC-{str(uuid.uuid4())[:8].upper()}"
    logger.info(f"Starting investigation for case {case_id}")

    try:
        # Extract text from evidence
        from utils.evidence_extraction import extract_text_from_content
        text_content = extract_text_from_content(evidence.content, evidence.type)

        # Store evidence in S3 if configured
        s3_key = store_evidence(case_id, evidence.content, getattr(evidence, 'content_type', 'text/plain'))
        if s3_key:
            logger.info(f"Evidence stored in S3 with key: {s3_key}")

        # Initialize agents
        evidence_agent = EvidenceAgent()
        social_engineering_agent = SocialEngineeringAgent()
        threat_intelligence_agent = ThreatIntelligenceAgent()
        devils_advocate_agent = DevilsAdvocateAgent()
        judge_agent = JudgeAgent()

        # Run agent analyses in parallel for efficiency
        evidence_task = asyncio.create_task(evidence_agent.analyze(text_content))
        social_task = asyncio.create_task(social_engineering_agent.analyze(text_content))
        threat_task = asyncio.create_task(threat_intelligence_agent.analyze(text_content))

        # Wait for the first three agents to complete
        evidence_result, social_result, threat_result = await asyncio.gather(
            evidence_task, social_task, threat_task
        )

        # Run Devil's Advocate agent (needs results from other agents)
        devils_advocate_result = await devils_advocate_agent.analyze(
            evidence_result, social_result, threat_result
        )

        # Run Judge agent (needs all results)
        verdict = await judge_agent.analyze(
            evidence_content=text_content,
            evidence_type=evidence.type,
            evidence_result=evidence_result,
            social_engineering_result=social_result,
            threat_intelligence_result=threat_result,
            devils_advocate_result=devils_advocate_result
        )

        # Extract evidence for the response
        from utils.evidence_extraction import extract_evidence
        extracted_evidence = extract_evidence(evidence.content, evidence.type)

        # Prepare the investigation result
        result = InvestigationResult(
            case_id=case_id,
            evidence=Evidence(
                type=evidence.type,
                content=evidence.content,
                metadata=evidence.metadata
            ),
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

        # Store the investigation result using the appropriate persistence layer
        persistence_mode = get_persistence_layer()
        investigation_result_dict = result.dict()

        if persistence_mode == "dynamodb":
            store_investigation(case_id, investigation_result_dict)
        else:  # memory mode
            _investigation_store[case_id] = result

        logger.info(f"Investigation completed for case {case_id}")
        return result

    except Exception as e:
        logger.error(f"Error during investigation for case {case_id}: {str(e)}")
        # Return a safe fallback result
        fallback_verdict = Verdict(
            risk_level="LOW",
            confidence=0.5,
            reasoning=["Error occurred during investigation analysis"],
            recommended_actions=["Please try again or consult with security professionals"]
        )

        return InvestigationResult(
            case_id=case_id,
            evidence=Evidence(
                type=evidence.type,
                content=evidence.content,
                metadata=evidence.metadata
            ),
            extracted_evidence=ExtractedEvidence(),
            agents={
                "evidence": {"findings": [], "indicators": []},
                "social_engineering": {"findings": [], "indicators": []},
                "threat_intelligence": {"findings": [], "indicators": []}
            },
            devils_advocate=DevilsAdvocateResult(),
            verdict=fallback_verdict,
            timestamp=datetime.utcnow().isoformat() + "Z"
        )


@app.post("/investigate/{case_id}/challenge", response_model=Dict[str, Any])
async def challenge_verdict(case_id: str):
        """
        Attack the current verdict by generating new challenges via Devil's Advocate
        and producing a revised verdict from the Judge.
        """
        logger.info(f"Attacking verdict for case {case_id}")

        # Retrieve the existing investigation using the appropriate persistence layer
        persistence_mode = get_persistence_layer()

        if persistence_mode == "dynamodb":
            investigation_data = get_investigation(case_id)
            if investigation_data is None:
                raise HTTPException(status_code=404, detail=f"Case {case_id} not found")
            original_result = InvestigationResult.parse_obj(investigation_data)
        else:  # memory mode
            if case_id not in _investigation_store:
                raise HTTPException(status_code=404, detail=f"Case {case_id} not found")
            original_result = _investigation_store[case_id]

        # Re-run Devil's Advocate to generate NEW challenges
        devils_advocate_agent = DevilsAdvocateAgent()
        new_challenges_result = await devils_advocate_agent.analyze(
            original_result.agents["evidence"],
            original_result.agents["social_engineering"],
            original_result.agents["threat_intelligence"]
        )

        # Run Judge again with the new challenges to get a revised verdict
        judge_agent = JudgeAgent()
        revised_verdict = await judge_agent.analyze(
            evidence_content=original_result.evidence.content,
            evidence_type=original_result.evidence.type,
            evidence_result=original_result.agents["evidence"],
            social_engineering_result=original_result.agents["social_engineering"],
            threat_intelligence_result=original_result.agents["threat_intelligence"],
            devils_advocate_result=new_challenges_result
        )

        # Determine what changed between the verdicts
        what_changed = []
        if original_result.verdict.risk_level != revised_verdict.risk_level:
            what_changed.append(f"Risk level changed from {original_result.verdict.risk_level} to {revised_verdict.risk_level}")

        if abs(original_result.verdict.confidence - revised_verdict.confidence) > 0.1:
            what_changed.append(f"Confidence changed from {original_result.verdict.confidence:.2f} to {revised_verdict.confidence:.2f}")

        # Prepare the response
        response = {
            "case_id": case_id,
            "previous_verdict": original_result.verdict.dict(),
            "new_challenges": new_challenges_result.get("challenges", []),
            "revised_verdict": revised_verdict.dict(),
            "what_changed": what_changed if what_changed else ["No significant changes in verdict"]
        }

        # Update the stored investigation with the revised verdict
        updated_result = InvestigationResult(
            case_id=original_result.case_id,
            evidence=original_result.evidence,
            extracted_evidence=original_result.extracted_evidence,
            agents=original_result.agents,
            devils_advocate=DevilsAdvocateResult(
    challenges=new_challenges_result.get("challenges", []),
    counter_evidence=new_challenges_result.get("counter_evidence", [])
),
            verdict=revised_verdict,
            timestamp=original_result.timestamp
        )
        # Persist the updated investigation using the appropriate persistence layer
        persistence_mode = get_persistence_layer()
        if persistence_mode == "dynamodb":
            store_investigation(case_id, updated_result.dict())
        else:  # memory mode
            _investigation_store[case_id] = updated_result

        logger.info(f"Challenge completed for case {case_id}")
        return response



if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8001))
    uvicorn.run(app, host="0.0.0.0", port=port)