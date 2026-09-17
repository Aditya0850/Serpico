from models.investigation import AgentFinding
import logging
from typing import List, Dict, Any
import re

logger = logging.getLogger(__name__)

class DevilsAdvocateAgent:
    """
    Devil's Advocate Agent responsible for generating alternative explanations and challenging assumptions.
    This agent tries to refute the findings from other agents by looking for:
    - Alternative explanations
    - Weak assumptions
    - Missing information
    - Contradictions in the evidence
    """

    def __init__(self):
        self.name = "Devil's Advocate Agent"

    async def analyze(self,
                     evidence_result: dict,
                     social_engineering_result: dict,
                     threat_intelligence_result: dict) -> Dict[str, Any]:
        """
        Analyze the results from other agents to generate challenges and counter-evidence.

        Args:
            evidence_result: Results from Evidence Agent
            social_engineering_result: Results from Social Engineering Agent
            threat_intelligence_result: Results from Threat Intelligence Agent

        Returns:
            Dictionary containing challenges and counter-evidence
        """
        try:
            logger.info(f"{self.name}: Generating challenges and counter-evidence")

            challenges = []
            counter_evidence = []

            # Generate challenges based on evidence result
            challenges.extend(self._challenge_evidence(evidence_result))
            challenges.extend(self._challenge_social_engineering(social_engineering_result))
            challenges.extend(self._challenge_threat_intelligence(threat_intelligence_result))

            # Generate counter-evidence (points that might suggest legitimacy)
            counter_evidence.extend(self._generate_counter_evidence(evidence_result))
            counter_evidence.extend(self._generate_counter_evidence(social_engineering_result))
            counter_evidence.extend(self._generate_counter_evidence(threat_intelligence_result))

            logger.info(f"{self.name}: Generated {len(challenges)} challenges and {len(counter_evidence)} counter-evidence items")

            return {
                "challenges": [finding.dict() for finding in challenges],
                "counter_evidence": [finding.dict() for finding in counter_evidence]
            }

        except Exception as e:
            logger.error(f"{self.name}: Error during analysis: {str(e)}")
            return {
                "challenges": [],
                "counter_evidence": [],
                "error": str(e)
            }

    def _challenge_evidence(self, evidence_result: dict) -> List[AgentFinding]:
        """Generate challenges to evidence agent findings"""
        challenges = []
        if not evidence_result or "findings" not in evidence_result:
            return challenges

        findings = evidence_result.get("findings", [])
        for finding in findings:
            if isinstance(finding, dict):
                f_type = finding.get("type", "")
                description = finding.get("description", "")
                confidence = finding.get("confidence", 0.5)
            else:
                f_type = getattr(finding, 'type', "")
                description = getattr(finding, 'description', "")
                confidence = getattr(finding, 'confidence', 0.5)

            # Generate challenges based on finding type
            if f_type == "url":
                challenges.append(AgentFinding(
                    type="alternative_explanation",
                    description=f"URL '{finding.get('evidence', '') if isinstance(finding, dict) else getattr(finding, 'evidence', '')}' could be legitimate or from a trusted source",
                    confidence=max(0.3, confidence - 0.3),
                    evidence="Legitimate businesses often use similar URLs for official communications"
                ))
            elif f_type == "monetary_amount":
                challenges.append(AgentFinding(
                    type="alternative_explanation",
                    description=f"Monetary amount '{finding.get('evidence', '') if isinstance(finding, dict) else getattr(finding, 'evidence', '')}' could be part of a legitimate transaction or invoice",
                    confidence=max(0.3, confidence - 0.2),
                    evidence="Reference to money does not automatically indicate fraudulent intent"
                ))
            elif f_type == "entity":
                challenges.append(AgentFinding(
                    type="alternative_explanation",
                    description=f"Entity '{finding.get('evidence', '') if isinstance(finding, dict) else getattr(finding, 'evidence', '')}' could be a legitimate organization being referenced",
                    confidence=max(0.3, confidence - 0.2),
                    evidence="Mention of an organization does not imply fraudulent activity"
                ))

        return challenges

    def _challenge_social_engineering(self, social_engineering_result: dict) -> List[AgentFinding]:
        """Generate challenges to social engineering agent findings"""
        challenges = []
        if not social_engineering_result or "findings" not in social_engineering_result:
            return challenges

        findings = social_engineering_result.get("findings", [])
        for finding in findings:
            if isinstance(finding, dict):
                f_type = finding.get("type", "")
                description = finding.get("description", "")
                confidence = finding.get("confidence", 0.5)
            else:
                f_type = getattr(finding, 'type', "")
                description = getattr(finding, 'description', "")
                confidence = getattr(finding, 'confidence', 0.5)

            # Generate challenges based on finding type
            if f_type == "urgency":
                challenges.append(AgentFinding(
                    type="alternative_explanation",
                    description=f"Urgency could be legitimate (e.g., time-sensitive offer, appointment reminder)",
                    confidence=max(0.3, confidence - 0.2),
                    evidence="Legitimate organizations sometimes use urgent language for valid reasons"
                ))
            elif f_type == "fear":
                challenges.append(AgentFinding(
                    type="alternative_explanation",
                    description=f"Fear-inducing language could be a legitimate warning (e.g., security breach notice)",
                    confidence=max(0.3, confidence - 0.2),
                    evidence="Organizations may need to warn users about real risks"
                ))
            elif f_type == "authority_impersonation":
                challenges.append(AgentFinding(
                    type="alternative_explanation",
                    description=f"Reference to authority could be legitimate (e.g., actual government agency communication)",
                    confidence=max(0.3, confidence - 0.3),
                    evidence="Not all references to authorities are impersonation attempts"
                ))
            elif f_type == "credential_request":
                challenges.append(AgentFinding(
                    type="alternative_explanation",
                    description=f"Request for information could be part of a legitimate service verification process",
                    confidence=max(0.3, confidence - 0.2),
                    evidence="Some services require verification for security purposes"
                ))

        return challenges

    def _challenge_threat_intelligence(self, threat_intelligence_result: dict) -> List[AgentFinding]:
        """Generate challenges to threat intelligence agent findings"""
        challenges = []
        if not threat_intelligence_result or "findings" not in threat_intelligence_result:
            return challenges

        findings = threat_intelligence_result.get("findings", [])
        for finding in findings:
            if isinstance(finding, dict):
                f_type = finding.get("type", "")
                description = finding.get("description", "")
                confidence = finding.get("confidence", 0.5)
            else:
                f_type = getattr(finding, 'type', "")
                description = getattr(finding, 'description', "")
                confidence = getattr(finding, 'confidence', 0.5)

            # Generate challenges based on finding type
            if f_type == "known_scam_domain":
                challenges.append(AgentFinding(
                    type="weak_assumption",
                    description=f"Domain matching might be coincidental or a false positive",
                    confidence=max(0.3, confidence - 0.3),
                    evidence="Similar domain names can be used by legitimate entities"
                ))
            elif f_type == "suspicious_tld":
                challenges.append(AgentFinding(
                    type="weak_assumption",
                    description=f"Use of suspicious TLD does not automatically indicate malicious intent",
                    confidence=max(0.3, confidence - 0.2),
                    evidence="Some legitimate organizations use less common TLDs for branding"
                ))
            elif f_type == "url_shortener":
                challenges.append(AgentFinding(
                    type="alternative_explanation",
                    description=f"URL shortening could be for legitimate purposes (e.g., character limits in social media)",
                    confidence=max(0.3, confidence - 0.2),
                    evidence="Many legitimate services use URL shorteners for tracking and convenience"
                ))
            elif f_type == "phishing_pattern":
                challenges.append(AgentFinding(
                    type="weak_assumption",
                    description=f"Pattern matching might be overly aggressive",
                    confidence=max(0.3, confidence - 0.2),
                    evidence="Legitimate URLs can sometimes match phishing patterns by coincidence"
                ))

        return challenges

    def _generate_counter_evidence(self, agent_result: dict) -> List[AgentFinding]:
        """Generate counter-evidence points that might suggest legitimacy"""
        counter_evidence = []
        if not agent_result or "findings" not in agent_result:
            return counter_evidence

        findings = agent_result.get("findings", [])
        for finding in findings:
            if isinstance(finding, dict):
                f_type = finding.get("type", "")
                description = finding.get("description", "")
                confidence = finding.get("confidence", 0.5)
            else:
                f_type = getattr(finding, 'type', "")
                description = getattr(finding, 'description', "")
                confidence = getattr(finding, 'confidence', 0.5)

            # Generate counter-evidence based on finding type
            if f_type in ["url", "monetary_amount", "entity"]:
                counter_evidence.append(AgentFinding(
                    type="legitimate_purpose",
                    description=f"The {f_type} could serve a legitimate business purpose",
                    confidence=max(0.4, confidence - 0.1),
                    evidence="Context is important - many legitimate communications contain similar elements"
                ))
            elif f_type in ["urgency", "fear", "authority_impersonation", "credential_request"]:
                counter_evidence.append(AgentFinding(
                    type="contextual_legitimacy",
                    description=f"The {f_type} could be appropriate in certain legitimate contexts",
                    confidence=max(0.4, confidence - 0.1),
                    evidence="Legitimate organizations sometimes use these tactics for important notifications"
                ))

        return counter_evidence