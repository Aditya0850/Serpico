from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from datetime import datetime
import uuid

class Evidence(BaseModel):
    type: str  # image, text, url
    content: str  # base64 for images, text content, or URL string
    metadata: Optional[Dict[str, Any]] = None

class ExtractedEvidence(BaseModel):
    text: str = ""
    urls: List[str] = []
    entities: List[str] = []
    indicators: List[str] = []

class AgentFinding(BaseModel):
    type: str
    description: str
    confidence: float
    evidence: Optional[str] = None

class AgentIndicators(BaseModel):
    indicators: List[str] = []

class EvidenceAgentResult(BaseModel):
    findings: List[AgentFinding] = []
    indicators: List[str] = []

class SocialEngineeringAgentResult(BaseModel):
    findings: List[AgentFinding] = []
    indicators: List[str] = []

class ThreatIntelligenceAgentResult(BaseModel):
    findings: List[AgentFinding] = []
    indicators: List[str] = []

class DevilsAdvocateResult(BaseModel):
    challenges: List[AgentFinding] = []
    counter_evidence: List[AgentFinding] = []

class Verdict(BaseModel):
    risk_level: str  # LOW, MEDIUM, HIGH, CRITICAL
    confidence: float  # 0.0 to 1.0
    reasoning: List[str] = []
    recommended_actions: List[str] = []

class InvestigationResult(BaseModel):
    case_id: str
    evidence: Evidence
    extracted_evidence: ExtractedEvidence
    agents: Dict[str, Any]
    devils_advocate: DevilsAdvocateResult
    verdict: Verdict
    timestamp: str

    @classmethod
    def create_case_id(cls) -> str:
        return f"TRC-{str(uuid.uuid4())[:8].upper()}"