import re
import base64
from typing import List
from models.investigation import ExtractedEvidence

def extract_text_from_content(content: str, evidence_type: str) -> str:
    """Extract text content based on evidence type"""
    if evidence_type == "text":
        return content
    elif evidence_type == "url":
        # For URL evidence, we'd normally fetch and extract text
        # For now, return placeholder
        return f"Content from URL: {content}"
    elif evidence_type == "image":
        # For image evidence, we'd use OCR or Bedrock Data Automation
        # For now, return placeholder
        return f"Text extracted from image (placeholder)"
    return ""

def extract_urls(text: str) -> List[str]:
    """Extract URLs from text using regex"""
    url_pattern = re.compile(
        r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    )
    return url_pattern.findall(text)

def extract_entities(text: str) -> List[str]:
    """Extract entities like organizations, persons, amounts from text"""
    entities = []

    # Simple regex patterns for common entities
    # Bank/Financial patterns
    bank_patterns = [
        r'\b(?:bank|credit union|financial institution)\b',
        r'\b(?:account|routing|swift|iban)\s*(?:number|#)?\s*\d+',
        r'\$\s*\d+(?:,\d{3})*(?:\.\d{2})?',
    ]

    for pattern in bank_patterns:
        matches = re.findall(pattern, text, re.IGNORECASE)
        entities.extend(matches)

    # Phone numbers
    phone_pattern = r'\b(?:\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b'
    phones = re.findall(phone_pattern, text)
    entities.extend([f"{p[0]}-{p[1]}-{p[2]}" for p in phones])

    # Email addresses
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    emails = re.findall(email_pattern, text)
    entities.extend(emails)

    return list(set(entities))  # Remove duplicates

def extract_indicators(text: str) -> List[str]:
    """Extract suspicious indicators from text"""
    indicators = []

    # Urgency indicators
    urgency_patterns = [
        r'\b(?:urgent|immediately|asap|right away|expires|deadline|limited time)\b',
        r'\b(?:act now|don\'t wait|time\s+sensitive)\b',
    ]

    # Fear/intimidation indicators
    fear_patterns = [
        r'\b(?:suspend|block|close|terminate|legal action|lawsuit|arrest)\b',
        r'\b(?:violation|penalty|fee|fine|owed|debt)\b',
    ]

    # Authority impersonation
    authority_patterns = [
        r'\b(?:fbi|irs|ssn|social security|internal revenue|federal)\b',
        r'\b(?:official|government|department|agency)\b',
    ]

    # Financial scam indicators
    financial_patterns = [
        r'\b(?:verify|confirm|update|validate).*?(?:account|information|details)\b',
        r'\b(?:prize|winner|won|lottery|inheritance|refund)\b',
        r'\b(?:wire transfer|moneygram|western union|gift card)\b',
    ]

    all_patterns = [
        (urgency_patterns, "urgency"),
        (fear_patterns, "fear"),
        (authority_patterns, "authority_impersonation"),
        (financial_patterns, "financial_scam")
    ]

    for patterns, indicator_type in all_patterns:
        for pattern in patterns:
            if re.search(pattern, text, re.IGNORECASE):
                indicators.append(indicator_type)
                break  # Only add each indicator type once per category

    return list(set(indicators))  # Remove duplicates

def extract_evidence(content: str, evidence_type: str) -> ExtractedEvidence:
    """Main function to extract evidence from content"""
    text = extract_text_from_content(content, evidence_type)
    urls = extract_urls(text)
    entities = extract_entities(text)
    indicators = extract_indicators(text)

    return ExtractedEvidence(
        text=text,
        urls=urls,
        entities=entities,
        indicators=indicators
    )