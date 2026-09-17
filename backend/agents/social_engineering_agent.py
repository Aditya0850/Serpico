from models.investigation import AgentFinding
import logging
import re
from typing import List, Dict, Any
from utils.evidence_extraction import extract_indicators

logger = logging.getLogger(__name__)

class SocialEngineeringAgent:
    """
    Social Engineering Agent responsible for detecting psychological manipulation tactics:
    - Urgency and pressure tactics
    - Fear and intimidation
    - Authority impersonation
    - Reward/lure tactics
    - Credential/request for sensitive information
    - Social proof and liking tactics
    """

    def __init__(self):
        self.name = "Social Engineering Agent"

    async def analyze(self, text: str) -> Dict[str, Any]:
        """
        Analyze text content for social engineering tactics.

        Args:
            text: The text content to analyze

        Returns:
            Dictionary containing findings and indicators
        """
        try:
            logger.info(f"{self.name}: Analyzing text for social engineering tactics")

            findings = []
            text_lower = text.lower()

            # Define social engineering patterns with types and descriptions
            se_patterns = {
                'urgency': [
                    (r'\b(?:urgent|urgently|immediately|asap|right away|expires|deadline|limited time|act now|don\'t wait|time\s+sensitive|warning|alert|notice)\b',
                     "Urgency tactic detected"),
                    (r'\b(?:expires\s+in|within\s+\d+\s+(?:hours?|days?|minutes?))\b',
                     "Time-based pressure detected")
                ],
                'fear': [
                    (r'\b(?:suspend|block|close|terminate|delete|lost|lost access|compromised|breach|hacked|unauthorized|suspicious activity)\b',
                     "Fear/intimidation tactic detected"),
                    (r'\b(?:legal action|lawsuit|arrest|fine|penalty|fee|owed|debt|collection|lawsuit)\b',
                     "Legal threat detected")
                ],
                'authority_impersonation': [
                    (r'\b(?:fbi|irs|ssn|social security|internal revenue|federal|bank|credit union|paypal|apple|microsoft|google|amazon|netflix)\b',
                     "Authority impersonation detected"),
                    (r'\b(?:official|government|department|agency|department of|bureau|administration)\b',
                     "Official entity impersonation detected")
                ],
                'reward_lure': [
                    (r'\b(?:prize|winner|won|lottery|inheritance|refund|reward|bonus|free gift|gift card|cash|money)\b.*\b(?:click|claim|visit|call|reply)\b',
                     "Reward/lure tactic detected"),
                    (r'\b(?:congratulations|you.?ve? won|you.?re? selected|exclusive offer|limited offer)\b',
                     "Winning/selection lure detected")
                ],
                'credential_request': [
                    (r'\b(?:verify|confirm|update|validate|secure|authenticate|login|sign in|password|pin|ssn|social security|account number|credit card|debit card)\b.*\b(?:information|details|data|credentials)\b',
                     "Credential/request for sensitive information detected"),
                    (r'\b(?:update\s+your|confirm\s+your|verify\s+your).*\b(?:account|profile|payment|billing)\b',
                     "Account information update request detected")
                ],
                'social_proof': [
                    (r'\b(?:act now|join\s+\d+\+|limited\s+spots|only\s+\d+\+|everyone\s+is|trusted\s+by|\d+\+.*users?|customers?|members?)\b',
                     "Social proof tactic detected"),
                    (r'\b(?:as\s+seen\s+in|featured\s+in|recommended\s+by|endorsed\s+by)\b',
                     "Endorsement/social proof detected")
                ],
                'scarcity': [
                    (r'\b(?:limited\s+time|limited\s+offer|only\s+\d+\+.*left|while\s+supplies\s+last|almost\s+gone|last\s+chance)\b',
                     "Scarcity tactic detected"),
                    (r'\b(?:act\s+fast|don\'t\s+miss|hurry\s+up|ending\s+soon)\b',
                     "Urgency through scarcity detected")
                ]
            }

            # Check each pattern category
            for se_type, patterns in se_patterns.items():
                for pattern, description in patterns:
                    if re.search(pattern, text_lower, re.IGNORECASE):
                        # Extract matching text for evidence
                        matches = re.findall(pattern, text_lower, re.IGNORECASE)
                        evidence = matches[0] if matches else description

                        findings.append(AgentFinding(
                            type=se_type,
                            description=description,
                            confidence=0.85,  # Base confidence for pattern match
                            evidence=str(evidence)[:100]  # Limit evidence length
                        ))

            # Additional contextual checks
            # Check for multiple SE tactics (increases confidence)
            unique_types = len(set(f.type for f in findings))
            if unique_types >= 3:
                # Boost confidence for multiple tactic detection
                for finding in findings:
                    finding.confidence = min(finding.confidence + 0.1, 0.95)

            logger.info(f"{self.name}: Detected {len(findings)} social engineering indicators")

            return {
                "findings": [finding.dict() for finding in findings],
                "indicators": list(set([f.type for f in findings]))  # Unique SE types
            }

        except Exception as e:
            logger.error(f"{self.name}: Error during analysis: {str(e)}")
            return {
                "findings": [],
                "indicators": [],
                "error": str(e)
            }