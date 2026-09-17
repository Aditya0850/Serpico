from models.investigation import AgentFinding
import logging
import re
from typing import List, Dict, Any
from utils.evidence_extraction import extract_urls, extract_entities, extract_indicators

logger = logging.getLogger(__name__)

class EvidenceAgent:
    """
    Evidence Agent responsible for extracting technical evidence from content:
    - URLs, domains, IP addresses
    - Entities (organizations, persons, financial info)
    - Monetary amounts
    - Basic indicators
    """

    def __init__(self):
        self.name = "Evidence Agent"

    async def analyze(self, text: str) -> Dict[str, Any]:
        """
        Analyze text content for evidence extraction.

        Args:
            text: The text content to analyze

        Returns:
            Dictionary containing findings and indicators
        """
        try:
            logger.info(f"{self.name}: Analyzing text for evidence extraction")

            findings = []

            # Extract URLs
            urls = extract_urls(text)
            for url in urls:
                findings.append(AgentFinding(
                    type="url",
                    description=f"Found URL: {url}",
                    confidence=0.8,
                    evidence=url
                ))

            # Extract entities (with focus on financial entities)
            entities = extract_entities(text)
            for entity in entities:
                # Check if it's a monetary amount
                if re.search(r'\$\s*\d+(?:,\d{3})*(?:\.\d{2})?', entity):
                    findings.append(AgentFinding(
                        type="monetary_amount",
                        description=f"Found monetary amount: {entity}",
                        confidence=0.9,
                        evidence=entity
                    ))
                else:
                    findings.append(AgentFinding(
                        type="entity",
                        description=f"Found entity: {entity}",
                        confidence=0.7,
                        evidence=entity
                    ))

            # Extract basic indicators
            indicators = extract_indicators(text)
            for indicator in indicators:
                findings.append(AgentFinding(
                    type=indicator,
                    description=f"Found {indicator} indicator",
                    confidence=0.6,
                    evidence=indicator
                ))

            logger.info(f"{self.name}: Extracted {len(findings)} evidence items")

            return {
                "findings": [finding.dict() for finding in findings],
                "indicators": list(set(indicators))  # Unique indicators
            }

        except Exception as e:
            logger.error(f"{self.name}: Error during analysis: {str(e)}")
            return {
                "findings": [],
                "indicators": [],
                "error": str(e)
            }