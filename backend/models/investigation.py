from pydantic import BaseModel, validator
from typing import List, Optional, Dict, Any
from datetime import datetime
import uuid
import json

class Evidence(BaseModel):
    type: str  # image, text, url
    content: str  # base64 for images, text content, or URL string
    metadata: Optional[Dict[str, Any]] = None

    @validator('content')
    def content_size_limit(cls, v):
        """Limit content to 5 MiB in UTF-8 bytes."""
        # 5 MiB = 5 * 1024 * 1024 bytes
        max_size = 5 * 1024 * 1024
        if len(v.encode('utf-8')) > max_size:
            raise ValueError(f'Content size exceeds limit of {max_size} bytes')
        return v

    @validator('metadata')
    def metadata_size_limit(cls, v):
        """Limit metadata to 100 KiB when serialized as JSON."""
        if v is None:
            return v
        # 100 KiB = 100 * 1024 bytes
        max_size = 100 * 1024
        # Serialize to JSON to get actual byte size
        serialized = json.dumps(v, sort_keys=True)  # sort_keys for deterministic serialization
        if len(serialized.encode('utf-8')) > max_size:
            raise ValueError(f'Metadata size exceeds limit of {max_size} bytes when serialized')
        return v

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