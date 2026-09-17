# DynamoDB storage utility for TRACE investigation state
# Imports: boto3, config, logging, datetime
# Called by: /investigate endpoint in main.py (to store) and potentially a GET endpoint (to retrieve)
# Affected API: POST /investigate in main.py (for storage) and future GET /investigate/{case_id} (for retrieval)
# Data schemas: Stores the entire InvestigationResult as a JSON-serializable dictionary under the 'investigation_data' attribute
# User's verbatim instruction: Persist investigation state. Minimum useful structure: PK = CASE#{case_id}

import boto3
import json
import logging
from typing import Optional, Dict, Any
from datetime import datetime
from config import aws_config

logger = logging.getLogger(__name__)

def store_investigation(case_id: str, investigation_data: Dict[str, Any]) -> bool:
    """
    Store investigation data in DynamoDB if DynamoDB is configured.

    Args:
        case_id: The investigation case ID
        investigation_data: The investigation data to store (should be JSON serializable)

    Returns:
        True if stored successfully, False if DynamoDB is not configured or storage failed
    """
    if not aws_config.is_dynamodb_configured():
        logger.info("DynamoDB not configured, skipping investigation persistence")
        return False

    try:
        dynamodb = boto3.resource(
            service_name='dynamodb',
            region_name=aws_config.aws_region
        )

        table = dynamodb.Table(aws_config.dynamodb_table)

        # Prepare the item for storage
        item = {
            'PK': f'CASE#{case_id}',  # Partition key
            'SK': 'METADATA',         # Sort key (we can use this for different types of data later)
            'case_id': case_id,
            'investigation_data': investigation_data,
            'timestamp': datetime.utcnow().isoformat() + "Z",
            'ttl': int(datetime.utcnow().timestamp()) + (30 * 24 * 60 * 60)  # 30 days TTL
        }

        # Put the item in DynamoDB
        table.put_item(Item=item)

        logger.info(f"Stored investigation for case {case_id} in DynamoDB table {aws_config.dynamodb_table}")
        return True

    except Exception as e:
        logger.error(f"Failed to store investigation for case {case_id} in DynamoDB: {str(e)}")
        return False

def get_investigation(case_id: str) -> Optional[Dict[str, Any]]:
    """
    Retrieve investigation data from DynamoDB if DynamoDB is configured.

    Args:
        case_id: The investigation case ID

    Returns:
        The investigation data if found, None if not found or DynamoDB is not configured
    """
    if not aws_config.is_dynamodb_configured():
        logger.info("DynamoDB not configured, skipping investigation retrieval")
        return None

    try:
        dynamodb = boto3.resource(
            service_name='dynamodb',
            region_name=aws_config.aws_region
        )

        table = dynamodb.Table(aws_config.dynamodb_table)

        # Get the item from DynamoDB
        response = table.get_item(
            Key={
                'PK': f'CASE#{case_id}',
                'SK': 'METADATA'
            }
        )

        if 'Item' in response:
            item = response['Item']
            logger.info(f"Retrieved investigation for case {case_id} from DynamoDB table {aws_config.dynamodb_table}")
            return item.get('investigation_data')
        else:
            logger.info(f"No investigation found for case {case_id} in DynamoDB")
            return None

    except Exception as e:
        logger.error(f"Failed to retrieve investigation for case {case_id} from DynamoDB: {str(e)}")
        return None