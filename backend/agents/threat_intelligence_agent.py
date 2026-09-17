from models.investigation import AgentFinding
import logging
import re
from typing import List, Dict, Any
from utils.evidence_extraction import extract_urls

logger = logging.getLogger(__name__)

class ThreatIntelligenceAgent:
    """
    Threat Intelligence Agent responsible for analyzing URLs and domains against known threats:
    - Known scam/fraud domains
    - Suspicious TLDs
    - URL shorteners
    - Phishing patterns
    - Domain age/reputation indicators (simulated)
    """

    def __init__(self):
        self.name = "Threat Intelligence Agent"
        # Known scam/fraud domains (in practice, this would come from a threat feed)
        self.known_scam_domains = {
            'paypa1.com', 'amaz0n-security.com', 'appleid-verification.com',
            'microsoft-support.net', 'google-login.org', 'faceb00k-security.com',
            'netflix-billing.com', 'dropbox-verification.com', 'icloud-alert.com'
        }

        # Suspicious TLDs often used in scams
        self.suspicious_tlds = {
            '.tk', '.ml', '.ga', '.cf', '.gq', '.work', '.party',
            '.science', '.download', '.stream', '.race', '.review',
            '.country', '.kim', '.cricket', '.party', '.science'
        }

        # Common URL shorteners
        self.url_shorteners = {
            'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly',
            'buff.ly', 'adf.ly', 'bit.do', 'mcaf.ee', 'is.gd'
        }

    async def analyze(self, text: str) -> Dict[str, Any]:
        """
        Analyze text content for threat intelligence indicators.

        Args:
            text: The text content to analyze

        Returns:
            Dictionary containing findings and indicators
        """
        try:
            logger.info(f"{self.name}: Analyzing text for threat intelligence")

            findings = []

            # Extract URLs from text
            urls = extract_urls(text)

            for url in urls:
                url_lower = url.lower()

                # Check for known scam domains
                for scam_domain in self.known_scam_domains:
                    if scam_domain in url_lower:
                        findings.append(AgentFinding(
                            type="known_scam_domain",
                            description=f"URL matches known scam domain: {scam_domain}",
                            confidence=0.95,
                            evidence=url
                        ))
                        break  # Only report once per URL

                # Check for suspicious TLDs
                for tld in self.suspicious_tlds:
                    if url_lower.endswith(tld):
                        findings.append(AgentFinding(
                            type="suspicious_tld",
                            description=f"URL uses suspicious TLD: {tld}",
                            confidence=0.8,
                            evidence=url
                        ))
                        break  # Only report once per URL

                # Check for URL shorteners
                for shortener in self.url_shorteners:
                    if shortener in url_lower:
                        findings.append(AgentFinding(
                            type="url_shortener",
                            description=f"URL uses shortening service: {shortener}",
                            confidence=0.75,
                            evidence=url
                        ))
                        break  # Only report once per URL

                # Check for phishing patterns in URL
                phishing_patterns = [
                    r'[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+',  # IP address in URL
                    r'(?:secure|account|update|verify|confirm|login|signin).*[0-9]+',  # Numbers in auth context
                    r'[a-zA-Z0-9]+-[a-zA-Z0-9]+.*\.(?:tk|ml|ga|cf|gq)',  # Hyphenated domains with suspicious TLD
                ]

                for pattern in phishing_patterns:
                    if re.search(pattern, url_lower, re.IGNORECASE):
                        findings.append(AgentFinding(
                            type="phishing_pattern",
                            description=f"URL matches phishing pattern: {pattern}",
                            confidence=0.85,
                            evidence=url
                        ))
                        break  # Only report once per URL for phishing pattern

            # Check for domain reputation indicators (simulated)
            # In practice, this would query threat intelligence feeds
            domain_indicators = self._check_domain_indicators(text)
            findings.extend(domain_indicators)

            logger.info(f"{self.name}: Identified {len(findings)} threat intelligence indicators")

            return {
                "findings": [finding.dict() for finding in findings],
                "indicators": list(set([f.type for f in findings]))  # Unique threat types
            }

        except Exception as e:
            logger.error(f"{self.name}: Error during analysis: {str(e)}")
            return {
                "findings": [],
                "indicators": [],
                "error": str(e)
            }

    def _check_domain_indicators(self, text: str) -> List[AgentFinding]:
        """Check for domain-based threat indicators"""
        findings = []

        # Extract potential domains for analysis
        url_pattern = re.compile(
            r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        )
        urls = url_pattern.findall(text)

        for url in urls:
            # Simulate domain age check (newly registered domains are riskier)
            # In practice, this would use WHOIS or DNS lookup
            if any(indicator in url.lower() for indicator in ['new', 'fresh', 'latest', 'update']):
                findings.append(AgentFinding(
                    type="newly_registered_domain",
                    description="Domain characteristics suggest recent registration",
                    confidence=0.6,
                    evidence=url
                ))

            # Check for typosquatting patterns
            if self._is_potential_typosquatting(url):
                findings.append(AgentFinding(
                    type="typosquatting",
                    description="Domain may be attempting typosquatting of legitimate brand",
                    confidence=0.7,
                    evidence=url
                ))

        return findings

    def _is_potential_typosquatting(self, url: str) -> bool:
        """Simple heuristic for potential typosquatting"""
        legitimate_brands = ['paypal', 'amazon', 'apple', 'microsoft', 'google', 'facebook', 'netflix']
        url_lower = url.lower()

        for brand in legitimate_brands:
            # Check for common typosquatting patterns
            if (len(brand) <= len(url_lower) and
                any(variant in url_lower for variant in [
                    brand.replace('a', '@'),
                    brand.replace('o', '0'),
                    brand.replace('i', '1'),
                    brand.replace('s', '5'),
                    brand + 'secure',
                    brand + 'login',
                    brand + 'verify'
                ])):
                    # More precise check
                    if ('@' in url_lower and brand.replace('a', '@') in url_lower) or \
                       ('0' in url_lower and brand.replace('o', '0') in url_lower) or \
                       ('1' in url_lower and brand.replace('i', '1') in url_lower) or \
                       ('5' in url_lower and brand.replace('s', '5') in url_lower) or \
                       (f'{brand}secure' in url_lower) or \
                       (f'{brand}login' in url_lower) or \
                       (f'{brand}verify' in url_lower):
                        return True
        return False