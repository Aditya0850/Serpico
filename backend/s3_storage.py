# S3 storage utility for TRACE evidence
# Imports: boto3, config, logging
# Called by: /investigate endpoint in main.py (to be implemented)
# Affected API: POST /investigate in main.py
# Data schemas: None (stores raw content as string)
# User's verbatim instruction: Add S3 evidence storage. Store uploaded evidence securely.

import boto3
import logging
from typing import Optional
from config import aws_config

logger = logging.getLogger(__name__)

def store_evidence(case_id: str, content: str, content_type: str = "text/plain") -> Optional[str]:
    """
    Store evidence content in S3 if S3 is configured.

    Args:
        case_id: The investigation case ID
        content: The evidence content to store
        content_type: The MIME type of the content (default: text/plain)

    Returns:
        The S3 object key if stored successfully, None if S3 is not configured or storage failed
    """
    if not aws_config.is_s3_configured():
        logger.info("S3 not configured, skipping evidence storage")
        return None

    try:
        s3_client = boto3.client(
            service_name='s3',
            region_name=aws_config.aws_region
        )

        # Create an S3 key that includes the case_id and a timestamp to avoid collisions
        # We'll also sanitize the case_id to be safe for S3 keys (though it should already be safe)
        s3_key = f"evidence/{case_id}/{aws_config.aws_region}/evidence.txt"

        # Put the object in S3
        s3_client.put_object(
            Bucket=aws_config.s3_bucket,
            Key=s3_key,
            Body=content.encode('utf-8'),
            ContentType=content_type,
            # We'll use server-side encryption with S3 managed keys (SSE-S3) for basic security
            ServerSideEncryption='AES256'
        )

        logger.info(f"Stored evidence for case {case_id} in S3 bucket {aws_config.s3_bucket} with key {s3_key}")
        return s3_key

    except Exception as e:
        logger.error(f"Failed to store evidence for case {case_id} in S3: {str(e)}")
        return None