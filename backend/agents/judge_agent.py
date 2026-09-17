from models.investigation import Verdict, AgentFinding
import logging
from typing import List, Dict, Any, Optional
import json
import boto3
from config import aws_config

logger = logging.getLogger(__name__)

class JudgeAgent:
    """
    Judge Agent that synthesizes all investigation findings and produces the final evidence-backed assessment.
    """

    def __init__(self):
        self.name = "Judge Agent"
        self.bedrock_client = None
        if aws_config.is_bedrock_configured():
            try:
                self.bedrock_client = boto3.client(
                    service_name='bedrock-runtime',
                    region_name=aws_config.aws_region
                )
                logger.info(f"{self.name}: Bedrock client initialized")
            except Exception as e:
                logger.warning(f"{self.name}: Failed to initialize Bedrock client: {e}")
                self.bedrock_client = None

    async def analyze(self,
                     evidence_content: str,
                     evidence_type: str,
                     evidence_result: dict,
                     social_engineering_result: dict,
                     threat_intelligence_result: dict,
                     devils_advocate_result: dict) -> Verdict:
        """
        Analyze all investigation results and produce final verdict.

        Args:
            evidence_content: Original evidence content
            evidence_type: Type of evidence
            evidence_result: Results from Evidence Agent
            social_engineering_result: Results from Social Engineering Agent
            threat_intelligence_result: Results from Threat Intelligence Agent
            devils_advocate_result: Results from Devil's Advocate Agent

        Returns:
            Verdict containing final risk assessment, confidence, reasoning, and recommendations
        """
        try:
            logger.info(f"{self.name}: Synthesizing investigation findings for final verdict")

            # Try to use Bedrock if available
            if self.bedrock_client is not None:
                try:
                    bedrock_verdict = await self._analyze_with_bedrock(
                        evidence_content=evidence_content,
                        evidence_type=evidence_type,
                        evidence_result=evidence_result,
                        social_engineering_result=social_engineering_result,
                        threat_intelligence_result=threat_intelligence_result,
                        devils_advocate_result=devils_advocate_result
                    )
                    if bedrock_verdict is not None:
                        logger.info(f"{self.name}: Bedrock verdict generated - Risk: {bedrock_verdict.risk_level}, Confidence: {bedrock_verdict.confidence:.2f}")
                        return bedrock_verdict
                except Exception as bedrock_error:
                    logger.warning(f"{self.name}: Bedrock analysis failed, falling back to rule-based: {bedrock_error}")

            # Fallback to rule-based analysis
            logger.info(f"{self.name}: Using rule-based analysis")

            # Calculate risk score based on agent findings
            risk_score = self._calculate_risk_score(
                evidence_result,
                social_engineering_result,
                threat_intelligence_result
            )

            # Adjust risk score based on Devil's Advocate challenges
            adjusted_risk_score = self._adjust_for_challenges(
                risk_score,
                devils_advocate_result
            )

            # Determine risk level based on adjusted score
            risk_level = self._determine_risk_level(adjusted_risk_score)

            # Calculate confidence based on evidence quality and consistency
            confidence = self._calculate_confidence(
                evidence_result,
                social_engineering_result,
                threat_intelligence_result,
                devils_advocate_result
            )

            # Generate reasoning
            reasoning = self._generate_reasoning(
                evidence_result,
                social_engineering_result,
                threat_intelligence_result,
                devils_advocate_result,
                risk_level
            )

            # Generate recommended actions
            recommended_actions = self._generate_recommended_actions(
                risk_level,
                evidence_result,
                social_engineering_result,
                threat_intelligence_result
            )

            logger.info(f"{self.name}: Verdict generated - Risk: {risk_level}, Confidence: {confidence:.2f}")

            return Verdict(
                risk_level=risk_level,
                confidence=confidence,
                reasoning=reasoning,
                recommended_actions=recommended_actions
            )

        except Exception as e:
            logger.error(f"{self.name}: Error during analysis: {str(e)}")
            # Return a safe default verdict on error
            return Verdict(
                risk_level="LOW",
                confidence=0.5,
                reasoning=["Error occurred during investigation analysis"],
                recommended_actions=["Please try again or consult with security professionals"]
            )

    def _calculate_risk_score(self, evidence_result: dict, social_engineering_result: dict, threat_intelligence_result: dict) -> float:
        """Calculate base risk score from agent findings"""
        score = 0.0
        max_score = 0.0

        # Evidence Agent contributes to risk (suspicious URLs, amounts, etc.)
        evidence_weight = 0.25
        evidence_score = self._calculate_agent_risk(evidence_result)
        score += evidence_score * evidence_weight
        max_score += evidence_weight

        # Social Engineering Agent is high weight (strong indicator of scams)
        social_weight = 0.4
        social_score = self._calculate_agent_risk(social_engineering_result)
        score += social_score * social_weight
        max_score += social_weight

        # Threat Intelligence Agent contributes to risk
        threat_weight = 0.35
        threat_score = self._calculate_agent_risk(threat_intelligence_result)
        score += threat_score * threat_weight
        max_score += threat_weight

        # Normalize score to 0-1 range
        if max_score > 0:
            return min(score / max_score, 1.0)
        return 0.0

    def _calculate_agent_risk(self, agent_result: dict) -> float:
        """Calculate risk contribution from a single agent's findings"""
        if not agent_result or "findings" not in agent_result:
            return 0.0

        findings = agent_result.get("findings", [])
        if not findings:
            return 0.0

        # Weight findings by confidence and type
        total_weight = 0.0
        weighted_sum = 0.0

        for finding in findings:
            if isinstance(finding, dict):
                confidence = finding.get("confidence", 0.5)
                # Certain finding types are inherently more risky
                type_multiplier = self._get_type_risk_multiplier(finding.get("type", ""))
                weight = confidence * type_multiplier
            else:
                # Handle AgentFinding objects
                confidence = getattr(finding, 'confidence', 0.5)
                type_multiplier = self._get_type_risk_multiplier(getattr(finding, 'type', ""))
                weight = confidence * type_multiplier

            weighted_sum += weight
            total_weight += 1.0

        if total_weight > 0:
            return min(weighted_sum / total_weight, 1.0)
        return 0.0

    def _get_type_risk_multiplier(self, finding_type: str) -> float:
        """Get risk multiplier based on finding type"""
        high_risk_types = {
            "authority_impersonation": 1.0,
            "credential_request": 1.0,
            "payment_pressure": 1.0,
            "known_scam_domain": 1.0,
            "phishing_pattern": 1.0,
            "urgency": 0.8,
            "fear": 0.8,
            "reward_lure": 0.7,
            "scam_keyword": 0.6,
            "suspicious_tld": 0.6,
            "url_shortener": 0.5,
            "monetary_amount": 0.4,
            "entity": 0.3
        }
        return high_risk_types.get(finding_type, 0.2)

    def _adjust_for_challenges(self, risk_score: float, devils_advocate_result: dict) -> float:
        """Adjust risk score based on Devil's Advocate challenges"""
        if not devils_advocate_result or "challenges" not in devils_advocate_result:
            return risk_score

        challenges = devils_advocate_result.get("challenges", [])
        if not challenges:
            return risk_score

        # Calculate challenge strength
        challenge_strength = 0.0
        for challenge in challenges:
            if isinstance(challenge, dict):
                confidence = challenge.get("confidence", 0.5)
                # Different challenge types have different weights
                type_weight = self._get_challenge_weight(challenge.get("type", ""))
                challenge_strength += confidence * type_weight
            else:
                confidence = getattr(challenge, 'confidence', 0.5)
                type_weight = self._get_challenge_weight(getattr(challenge, 'type', ""))
                challenge_strength += confidence * type_weight

        # Normalize challenge strength
        if challenges:
            challenge_strength = min(challenge_strength / len(challenges), 1.0)
        else:
            challenge_strength = 0.0

        # Reduce risk score based on challenge strength (but don't eliminate risk entirely)
        # Strong challenges can reduce risk by up to 40%
        reduction_factor = challenge_strength * 0.4
        adjusted_score = risk_score * (1.0 - reduction_factor)

        return max(adjusted_score, 0.1)  # Never reduce below 0.1 to avoid eliminating all risk

    def _get_challenge_weight(self, challenge_type: str) -> float:
        """Get weight for different challenge types"""
        challenge_weights = {
            "alternative_explanation": 0.8,
            "missing_information": 0.9,
            "weak_assumption": 0.7,
            "contradiction": 0.6
        }
        return challenge_weights.get(challenge_type, 0.5)

    def _determine_risk_level(self, risk_score: float) -> str:
        """Determine risk level based on score"""
        if risk_score >= 0.8:
            return "CRITICAL"
        elif risk_score >= 0.6:
            return "HIGH"
        elif risk_score >= 0.3:
            return "MEDIUM"
        else:
            return "LOW"

    def _calculate_confidence(self, evidence_result: dict, social_engineering_result: dict,
                            threat_intelligence_result: dict, devils_advocate_result: dict) -> float:
        """Calculate confidence in the verdict based on evidence quality"""
        # Base confidence on amount and quality of evidence
        total_findings = 0
        total_confidence = 0.0

        agents = [
            ("evidence", evidence_result),
            ("social_engineering", social_engineering_result),
            ("threat_intelligence", threat_intelligence_result)
        ]

        for agent_name, agent_result in agents:
            if agent_result and "findings" in agent_result:
                findings = agent_result.get("findings", [])
                for finding in findings:
                    if isinstance(finding, dict):
                        confidence = finding.get("confidence", 0.5)
                    else:
                        confidence = getattr(finding, 'confidence', 0.5)
                    total_confidence += confidence
                    total_findings += 1

        # Calculate average confidence from findings
        if total_findings > 0:
            avg_confidence = total_confidence / total_findings
        else:
            avg_confidence = 0.5

        # Adjust confidence based on consistency (Devil's Advocate challenges reduce confidence)
        consistency_factor = 1.0
        if devils_advocate_result and "challenges" in devils_advocate_result:
            challenge_count = len(devils_advocate_result.get("challenges", []))
            # More challenges = lower confidence in the original assessment
            consistency_factor = max(0.5, 1.0 - (challenge_count * 0.1))

        # Adjust based on conflicting findings (simple heuristic)
        conflict_factor = 1.0
        # In a more sophisticated implementation, we'd look for actual contradictions

        final_confidence = avg_confidence * consistency_factor * conflict_factor
        return max(0.3, min(final_confidence, 0.95))  # Clamp between 0.3 and 0.95

    def _generate_reasoning(self, evidence_result: dict, social_engineering_result: dict,
                          threat_intelligence_result: dict, devils_advocate_result: dict,
                          risk_level: str) -> List[str]:
        """Generate human-readable reasoning for the verdict"""
        reasoning = []

        # Add risk level context
        reasoning.append(f"Overall risk assessment: {risk_level}")

        # Add evidence-based reasoning
        if evidence_result and evidence_result.get("findings"):
            url_findings = [f for f in evidence_result["findings"] if f.get("type") == "url"]
            money_findings = [f for f in evidence_result["findings"] if f.get("type") == "monetary_amount"]
            if url_findings:
                reasoning.append(f"Found {len(url_findings)} suspicious URL(s) in the evidence")
            if money_findings:
                reasoning.append(f"Found {len(money_findings)} monetary reference(s) suggesting financial motive")

        # Add social engineering reasoning
        if social_engineering_result and social_engineering_result.get("findings"):
            urgency_count = len([f for f in social_engineering_result["findings"] if f.get("type") == "urgency"])
            authority_count = len([f for f in social_engineering_result["findings"] if f.get("type") == "authority_impersonation"])
            cred_count = len([f for f in social_engineering_result["findings"] if f.get("type") == "credential_request"])

            if urgency_count > 0:
                reasoning.append(f"Detected {urgency_count} urgency tactic(s) attempting to pressure immediate action")
            if authority_count > 0:
                reasoning.append(f"Detected {authority_count} instance(s) of authority impersonation")
            if cred_count > 0:
                reasoning.append(f"Detected {cred_count} request(s) for sensitive credentials or information")

        # Add threat intelligence reasoning
        if threat_intelligence_result and threat_intelligence_result.get("findings"):
            scam_domain_count = len([f for f in threat_intelligence_result["findings"] if f.get("type") == "known_scam_domain"])
            phishing_count = len([f for f in threat_intelligence_result["findings"] if f.get("type") == "phishing_pattern"])
            if scam_domain_count > 0:
                reasoning.append(f"Found {scam_domain_count} URL(s) matching known scam domains")
            if phishing_count > 0:
                reasoning.append(f"Found {phishing_count} indicator(s) matching known phishing patterns")

        # Add Devil's Advocate context
        if devils_advocate_result and devils_advocate_result.get("challenges"):
            challenge_count = len(devils_advocate_result.get("challenges", []))
            if challenge_count > 0:
                reasoning.append(f"Devil's Advocate identified {challenge_count} potential alternative explanations or weaknesses in the evidence")

        # Ensure we have at least some reasoning
        if not reasoning:
            reasoning.append("Analysis based on available evidence patterns and threat intelligence")

        return reasoning

    def _generate_recommended_actions(self, risk_level: str, evidence_result: dict,
                                    social_engineering_result: dict, threat_intelligence_result: dict) -> List[str]:
        """Generate recommended actions based on risk level and findings"""
        actions = []

        # Base actions by risk level
        if risk_level == "CRITICAL":
            actions.extend([
                "Do not interact with the message or click any links",
                "Immediately report to your organization's security team or relevant authorities",
                "Consider the message compromised and assume any provided information is fraudulent",
                "Monitor accounts closely for unauthorized activity"
            ])
        elif risk_level == "HIGH":
            actions.extend([
                "Do not click on any links or download attachments",
                "Do not provide any personal or financial information",
                "Verify the sender through official channels before taking any action",
                "Report the message as suspicious to relevant platforms or authorities"
            ])
        elif risk_level == "MEDIUM":
            actions.extend([
                "Exercise caution and verify independently before taking any action",
                "Do not provide sensitive information without verifying the request",
                "Research the sender or organization through independent sources",
                "Consider contacting the supposed sender through known official channels"
            ])
        else:  # LOW
            actions.extend([
                "Message appears low risk but maintain standard vigilance",
                "Verify unexpected requests through official channels",
                "Keep software and security measures up to date"
            ])

        # Add specific actions based on findings
        if evidence_result and evidence_result.get("findings"):
            url_findings = [f for f in evidence_result["findings"] if f.get("type") == "url"]
            if url_findings:
                actions.append("Do not click on any links in the message without verifying their destination")

        if social_engineering_result and social_engineering_result.get("findings"):
            cred_findings = [f for f in social_engineering_result["findings"] if f.get("type") == "credential_request"]
            if cred_findings:
                actions.append("Never provide passwords, SSN, or financial details in response to unsolicited messages")

        # Add general safety actions
        actions.append("When in doubt, contact the organization directly using known official contact information")
        actions.append("Report suspicious messages to help protect others from similar scams")

        # Remove duplicates while preserving order
        seen = set()
        unique_actions = []
        for action in actions:
            if action not in seen:
                seen.add(action)
                unique_actions.append(action)

        return unique_actions[:8]  # Limit to top 8 actions

    async def _analyze_with_bedrock(self,
                                  evidence_content: str,
                                  evidence_type: str,
                                  evidence_result: dict,
                                  social_engineering_result: dict,
                                  threat_intelligence_result: dict,
                                  devils_advocate_result: dict) -> Optional[Verdict]:
        """
        Analyze investigation results using Amazon Bedrock.

        Args:
            evidence_content: Original evidence content
            evidence_type: Type of evidence
            evidence_result: Results from Evidence Agent
            social_engineering_result: Results from Social Engineering Agent
            threat_intelligence_result: Results from Threat Intelligence Agent
            devils_advocate_result: Results from Devil's Advocate Agent

        Returns:
            Verdict containing final risk assessment, confidence, reasoning, and recommendations, or None if failed
        """
        try:
            # Prepare the prompt for Bedrock
            prompt = self._create_bedrock_prompt(
                evidence_content=evidence_content,
                evidence_type=evidence_type,
                evidence_result=evidence_result,
                social_engineering_result=social_engineering_result,
                threat_intelligence_result=threat_intelligence_result,
                devils_advocate_result=devils_advocate_result
            )

            # Call Bedrock
            model_id = aws_config.bedrock_model_id or "anthropic.claude-3-sonnet-20240229-v1:0"

            body = {
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": 1000,
                "temperature": 0.1,
                "messages": [
                    {
                        "role": "user",
                        "content": prompt
                    }
                ]
            }

            response = self.bedrock_client.invoke_model(
                modelId=model_id,
                body=json.dumps(body)
            )

            response_body = json.loads(response['body'].read())

            # Extract the text response
            if 'content' in response_body and len(response_body['content']) > 0:
                text_response = response_body['content'][0]['text']

                # Try to parse JSON from the response
                verdict_data = self._parse_verdict_from_text(text_response)
                if verdict_data:
                    return Verdict(**verdict_data)

            logger.warning(f"{self.name}: Could not parse structured verdict from Bedrock response")
            return None

        except Exception as e:
            logger.error(f"{self.name}: Error calling Bedrock: {str(e)}")
            return None

    def _create_bedrock_prompt(self,
                             evidence_content: str,
                             evidence_type: str,
                             evidence_result: dict,
                             social_engineering_result: dict,
                             threat_intelligence_result: dict,
                             devils_advocate_result: dict) -> str:
        """Create a structured prompt for Bedrock analysis"""

        # Format the findings for the prompt
        evidence_findings = self._format_findings_for_prompt(evidence_result.get("findings", []))
        social_findings = self._format_findings_for_prompt(social_engineering_result.get("findings", []))
        threat_findings = self._format_findings_for_prompt(threat_intelligence_result.get("findings", []))

        # Format challenges
        challenges = []
        if devils_advocate_result and "challenges" in devils_advocate_result:
            for challenge in devils_advocate_result["challenges"]:
                if isinstance(challenge, dict):
                    challenges.append(f"- {challenge.get('description', 'No description')} (confidence: {challenge.get('confidence', 0.5):.2f})")
                else:
                    challenges.append(f"- {getattr(challenge, 'description', 'No description')} (confidence: {getattr(challenge, 'confidence', 0.5):.2f})")

        prompt = f"""You are an expert cybersecurity analyst tasked with evaluating the risk level of digital communications for potential scams, fraud, or malicious intent.

Analyze the following evidence and agent findings to provide a comprehensive risk assessment:

ORIGINAL EVIDENCE:
Type: {evidence_type}
Content: {evidence_content[:500]}{"..." if len(evidence_content) > 500 else ""}

EVIDENCE AGENT FINDINGS:
{evidence_findings if evidence_findings else "No specific findings"}

SOCIAL ENGINEERING AGENT FINDINGS:
{social_findings if social_findings else "No specific findings"}

THREAT INTELLIGENCE AGENT FINDINGS:
{threat_findings if threat_findings else "No specific findings"}

DEVIL'S ADVOCATE CHALLENGES (potential alternative explanations or weaknesses):
{chr(10).join(challenges) if challenges else "No challenges identified"}

Based on all available information, provide your assessment in the following JSON format:
{{
    "risk_level": "LOW|MEDIUM|HIGH|CRITICAL",
    "confidence": 0.0-1.0,
    "reasoning": [
        "Specific reason 1 for the assessment",
        "Specific reason 2 for the assessment",
        "Specific reason 3 for the assessment"
    ],
    "recommended_actions": [
        "Specific action 1 to take",
        "Specific action 2 to take",
        "Specific action 3 to take"
    ]
}}

GUIDELINES:
- risk_level:
  * LOW: Minimal risk, likely legitimate communication
  * MEDIUM: Some suspicious elements requiring caution
  * HIGH: Strong indicators of scam/fraud/malicious intent
  * CRITICAL: Definitive scam/fraud with high confidence
- confidence: Your confidence in the assessment (0.0 to 1.0)
- reasoning: List of specific, evidence-based reasons for your assessment
- recommended_actions: List of specific, actionable steps for the user to take

Consider:
1. Technical indicators (suspicious URLs, domains, etc.)
2. Social engineering tactics (urgency, fear, authority impersonation)
3. Threat intelligence matches (known scam domains, phishing patterns)
4. Consistency and plausibility of the communication
5. Any challenges raised by the Devil's Advocate that weaken the assessment

Provide only the JSON object in your response, no additional text."""

        return prompt

    def _format_findings_for_prompt(self, findings: List[Dict[str, Any]]) -> str:
        """Format findings for inclusion in the Bedrock prompt"""
        if not findings:
            return "No specific findings"

        formatted = []
        for finding in findings:
            if isinstance(finding, dict):
                f_type = finding.get('type', 'unknown')
                description = finding.get('description', 'No description')
                confidence = finding.get('confidence', 0.5)
                formatted.append(f"- {f_type}: {description} (confidence: {confidence:.2f})")
            else:
                # Handle AgentFinding objects
                f_type = getattr(finding, 'type', 'unknown')
                description = getattr(finding, 'description', 'No description')
                confidence = getattr(finding, 'confidence', 0.5)
                formatted.append(f"- {f_type}: {description} (confidence: {confidence:.2f})")

        return "\n".join(formatted)

    def _parse_verdict_from_text(self, text: str) -> Optional[Dict[str, Any]]:
        """Parse verdict data from Bedrock text response"""
        try:
            # Try to find JSON in the response
            import re

            # Look for JSON object in the text
            json_match = re.search(r'\{[^{}]*"risk_level"[^{}]*\}', text, re.DOTALL)
            if json_match:
                json_str = json_match.group(0)
                verdict_data = json.loads(json_str)

                # Validate and normalize the data
                return self._validate_and_normalize_verdict(verdict_data)

            # If that fails, try to parse the whole text as JSON
            verdict_data = json.loads(text.strip())
            return self._validate_and_normalize_verdict(verdict_data)

        except json.JSONDecodeError as e:
            logger.warning(f"{self.name}: Failed to parse JSON from Bedrock response: {e}")
            logger.debug(f"{self.name}: Bedrock response text: {text[:200]}...")
            return None
        except Exception as e:
            logger.warning(f"{self.name}: Error parsing verdict from Bedrock response: {e}")
            return None

    def _validate_and_normalize_verdict(self, verdict_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Validate and normalize verdict data from Bedrock"""
        try:
            # Ensure required fields exist
            if not all(key in verdict_data for key in ["risk_level", "confidence", "reasoning", "recommended_actions"]):
                logger.warning(f"{self.name}: Missing required fields in Bedrock verdict")
                return None

            # Normalize risk level
            risk_level = str(verdict_data["risk_level"]).upper()
            if risk_level not in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
                # Try to map common variations
                risk_mapping = {
                    "LOW": "LOW",
                    "MEDIUM": "MEDIUM",
                    "HIGH": "HIGH",
                    "CRITICAL": "CRITICAL",
                    "L": "LOW",
                    "M": "MEDIUM",
                    "H": "HIGH",
                    "C": "CRITICAL"
                }
                risk_level = risk_mapping.get(risk_level, "LOW")

            # Normalize confidence
            try:
                confidence = float(verdict_data["confidence"])
                confidence = max(0.0, min(1.0, confidence))  # Clamp to 0-1
            except (ValueError, TypeError):
                confidence = 0.5

            # Ensure reasoning is a list of strings
            reasoning = verdict_data["reasoning"]
            if not isinstance(reasoning, list):
                reasoning = [str(reasoning)] if reasoning else ["Analysis based on available evidence"]
            reasoning = [str(item) for item in reasoning[:5]]  # Limit to 5 items

            # Ensure recommended_actions is a list of strings
            actions = verdict_data["recommended_actions"]
            if not isinstance(actions, list):
                actions = [str(actions)] if actions else ["Exercise caution and verify independently"]
            actions = [str(item) for item in actions[:8]]  # Limit to 8 items

            return {
                "risk_level": risk_level,
                "confidence": confidence,
                "reasoning": reasoning,
                "recommended_actions": actions
            }

        except Exception as e:
            logger.warning(f"{self.name}: Error validating Bedrock verdict: {e}")
            return None