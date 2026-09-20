import re
import base64
import ipaddress
import asyncio
import logging
from typing import List
from urllib.parse import urlparse

import httpx
from models.investigation import ExtractedEvidence

logger = logging.getLogger(__name__)

# Maximum response body size for URL fetching (1 MiB)
MAX_URL_RESPONSE_SIZE = 1 * 1024 * 1024

# Maximum decoded image size (5 MiB - matches content limit)
MAX_IMAGE_DECODED_SIZE = 5 * 1024 * 1024

# URL fetch timeout (5 seconds total)
URL_FETCH_TIMEOUT = 5.0

# Private/reserved IP ranges that must be blocked
BLOCKED_IP_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("ff00::/8"),
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("::ffff:0:0/96"),
    ipaddress.ip_network("2001:db8::/32"),
]

AWS_METADATA_IP = ipaddress.ip_address("169.254.169.254")


def is_ip_blocked(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip == AWS_METADATA_IP:
            return True
        for network in BLOCKED_IP_RANGES:
            if ip in network:
                return True
        return False
    except ValueError:
        return True


def validate_url_scheme(url: str) -> bool:
    parsed = urlparse(url)
    return parsed.scheme.lower() in ("http", "https")


async def resolve_and_validate_hostname(url: str) -> List[str]:
    parsed = urlparse(url)
    hostname = parsed.hostname
    if not hostname:
        raise ValueError("Invalid URL: no hostname")
    try:
        import socket
        loop = asyncio.get_event_loop()
        addrs = await loop.getaddrinfo(hostname, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise ValueError(f"DNS resolution failed: {e}")
    validated_ips = []
    for addr in addrs:
        ip = addr[4][0]
        if is_ip_blocked(ip):
            logger.warning(f"Blocked connection to private/internal IP: {ip} for host {hostname}")
            raise ValueError(f"Connection to private/internal address blocked: {ip}")
        validated_ips.append(ip)
    if not validated_ips:
        raise ValueError("No valid public IP addresses resolved")
    return validated_ips


async def fetch_url_content(url: str) -> str:
    if not validate_url_scheme(url):
        raise ValueError("Only http:// and https:// URLs are allowed")
    await resolve_and_validate_hostname(url)
    limits = httpx.Limits(max_connections=1, max_keepalive_connections=0)
    timeout = httpx.Timeout(connect=URL_FETCH_TIMEOUT, read=URL_FETCH_TIMEOUT, write=URL_FETCH_TIMEOUT, pool=URL_FETCH_TIMEOUT)
    async with httpx.AsyncClient(limits=limits, timeout=timeout, follow_redirects=False, max_redirects=0) as client:
        current_url = url
        redirect_count = 0
        max_redirects = 5
        while redirect_count <= max_redirects:
            await resolve_and_validate_hostname(current_url)
            try:
                async with client.stream("GET", current_url) as response:
                    if response.is_redirect:
                        redirect_count += 1
                        if redirect_count > max_redirects:
                            raise ValueError("Too many redirects")
                        location = response.headers.get("location")
                        if not location:
                            raise ValueError("Redirect without location header")
                        redirect_url = httpx.URL(current_url).join(location)
                        current_url = str(redirect_url)
                        continue
                    content_length = response.headers.get("content-length")
                    if content_length:
                        try:
                            if int(content_length) > MAX_URL_RESPONSE_SIZE:
                                raise ValueError(f"Response too large: {content_length} bytes")
                        except ValueError:
                            pass
                    content_bytes = bytearray()
                    async for chunk in response.aiter_bytes():
                        content_bytes.extend(chunk)
                        if len(content_bytes) > MAX_URL_RESPONSE_SIZE:
                            raise ValueError(f"Response exceeds {MAX_URL_RESPONSE_SIZE} byte limit")
                    content = content_bytes.decode("utf-8", errors="replace")
                    return extract_text_from_html(content)
            except httpx.TimeoutException:
                raise ValueError("Request timed out")
            except httpx.ConnectError as e:
                raise ValueError(f"Connection failed: {type(e).__name__}")
            except httpx.RequestError as e:
                raise ValueError(f"Request failed: {type(e).__name__}")
    raise ValueError("Max redirects exceeded")


def extract_text_from_html(html: str) -> str:
    if not html:
        return ""
    html = re.sub(r'<script[^>]*>.*?</script>', ' ', html, flags=re.IGNORECASE | re.DOTALL)
    html = re.sub(r'<style[^>]*>.*?</style>', ' ', html, flags=re.IGNORECASE | re.DOTALL)
    html = re.sub(r'<!--.*?-->', ' ', html, flags=re.DOTALL)
    block_tags = ['div', 'p', 'br', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'li', 'tr', 'td', 'th', 'section', 'article', 'header', 'footer', 'nav', 'main', 'aside', 'blockquote', 'pre', 'ul', 'ol', 'dl', 'dt', 'dd', 'table', 'thead', 'tbody', 'form', 'fieldset', 'legend', 'label', 'option', 'optgroup']
    for tag in block_tags:
        html = re.sub(f'<{tag}[^>]*>', '\n', html, flags=re.IGNORECASE)
        html = re.sub(f'</{tag}>', '\n', html, flags=re.IGNORECASE)
    html = re.sub(r'<[^>]+>', ' ', html)
    html = html.replace('&nbsp;', ' ').replace('&', '&').replace('<', '<').replace('>', '>').replace('"', '"').replace('&apos;', "'")
    html = re.sub(r'&#(\d+);', lambda m: chr(int(m.group(1))) if int(m.group(1)) < 0x110000 else '', html)
    html = re.sub(r'&#x([0-9a-fA-F]+);', lambda m: chr(int(m.group(1), 16)) if int(m.group(1), 16) < 0x110000 else '', html)
    text = re.sub(r'\s+', ' ', html)
    text = re.sub(r'\n\s*\n', '\n\n', text)
    return text.strip()


def extract_text_from_base64_image(b64_content: str) -> str:
    if not b64_content or not b64_content.strip():
        raise ValueError("Empty image content")
    if b64_content.startswith("data:"):
        try:
            comma_idx = b64_content.index(",")
            b64_content = b64_content[comma_idx + 1:]
        except ValueError:
            raise ValueError("Invalid data URL format")
    try:
        decoded = base64.b64decode(b64_content, validate=True)
    except Exception as e:
        raise ValueError(f"Invalid base64 encoding: {type(e).__name__}")
    if len(decoded) > MAX_IMAGE_DECODED_SIZE:
        raise ValueError(f"Decoded image exceeds {MAX_IMAGE_DECODED_SIZE} byte limit")
    if not is_valid_image_format(decoded):
        raise ValueError("Unsupported or invalid image format")
    return "[Image OCR not available: Text extraction from images requires OCR/vision model integration. The image has been validated and stored for future analysis.]"


def is_valid_image_format(data: bytes) -> bool:
    if len(data) < 4:
        return False
    if data[:8] == b'\x89PNG\r\n\x1a\n':
        return True
    if data[:3] == b'\xff\xd8\xff':
        return True
    if data[:4] == b'RIFF' and len(data) >= 12 and data[8:12] == b'WEBP':
        return True
    if data[:6] in (b'GIF87a', b'GIF89a'):
        return True
    if data[:2] == b'BM':
        return True
    if data[:2] in (b'II', b'MM'):
        return True
    return False


async def extract_text_from_content(content: str, evidence_type: str) -> str:
    import logging
    logger = logging.getLogger(__name__)
    logger.info(f"extract_text_from_content called with type={evidence_type}, content={content[:50]}")
    if evidence_type == "text":
        return content
    elif evidence_type == "url":
        try:
            logger.info(f"Fetching URL: {content}")
            result = await fetch_url_content(content)
            logger.info(f"URL fetch result length: {len(result)}")
            return result
        except ValueError as e:
            logger.warning(f"URL fetch failed for {content}: {e}")
            return f"[URL fetch failed: {str(e)}]"
        except Exception as e:
            logger.error(f"Unexpected error fetching URL {content}: {e}")
            return f"[URL fetch failed: Unexpected error]"
    elif evidence_type == "image":
        try:
            return extract_text_from_base64_image(content)
        except ValueError as e:
            logger.warning(f"Image validation failed: {e}")
            return f"[Invalid image: {str(e)}]"
        except Exception as e:
            logger.error(f"Unexpected error processing image: {e}")
            return f"[Image processing failed: Unexpected error]"
    return ""


def extract_urls(text: str) -> List[str]:
    url_pattern = re.compile(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')
    return url_pattern.findall(text)


def extract_entities(text: str) -> List[str]:
    entities = []
    bank_patterns = [
        r'\b(?:bank|credit union|financial institution)\b',
        r'\b(?:account|routing|swift|iban)\s*(?:number|#)?\s*\d+',
        r'\$\s*\d+(?:,\d{3})*(?:\.\d{2})?',
    ]
    for pattern in bank_patterns:
        matches = re.findall(pattern, text, re.IGNORECASE)
        entities.extend(matches)
    phone_pattern = r'\b(?:\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b'
    phones = re.findall(phone_pattern, text)
    entities.extend([f"{p[0]}-{p[1]}-{p[2]}" for p in phones])
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    emails = re.findall(email_pattern, text)
    entities.extend(emails)
    return list(set(entities))


def extract_indicators(text: str) -> List[str]:
    indicators = []
    urgency_patterns = [r'\b(?:urgent|immediately|asap|right away|expires|deadline|limited time)\b', r'\b(?:act now|don\'t wait|time\s+sensitive)\b']
    fear_patterns = [r'\b(?:suspend|block|close|terminate|legal action|lawsuit|arrest)\b', r'\b(?:violation|penalty|fee|fine|owed|debt)\b']
    authority_patterns = [r'\b(?:fbi|irs|ssn|social security|internal revenue|federal)\b', r'\b(?:official|government|department|agency)\b']
    financial_patterns = [r'\b(?:verify|confirm|update|validate).*?(?:account|information|details)\b', r'\b(?:prize|winner|won|lottery|inheritance|refund)\b', r'\b(?:wire transfer|moneygram|western union|gift card)\b']
    all_patterns = [(urgency_patterns, "urgency"), (fear_patterns, "fear"), (authority_patterns, "authority_impersonation"), (financial_patterns, "financial_scam")]
    for patterns, indicator_type in all_patterns:
        for pattern in patterns:
            if re.search(pattern, text, re.IGNORECASE):
                indicators.append(indicator_type)
                break
    return list(set(indicators))


async def extract_evidence(content: str, evidence_type: str) -> ExtractedEvidence:
    text = await extract_text_from_content(content, evidence_type)
    urls = extract_urls(text)
    entities = extract_entities(text)
    indicators = extract_indicators(text)
    return ExtractedEvidence(text=text, urls=urls, entities=entities, indicators=indicators)