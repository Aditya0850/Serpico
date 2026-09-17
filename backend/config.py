import os
from typing import Optional

class AWSConfig:
    """AWS configuration loaded from environment variables."""

    def __init__(self):
        self.aws_region: Optional[str] = os.getenv("AWS_REGION")
        self.bedrock_model_id: Optional[str] = os.getenv("BEDROCK_MODEL_ID")
        self.s3_bucket: Optional[str] = os.getenv("S3_BUCKET")
        self.dynamodb_table: Optional[str] = os.getenv("DYNAMODB_TABLE")

    def is_configured(self) -> bool:
        """Check if basic AWS configuration is present."""
        return bool(self.aws_region)

    def is_bedrock_configured(self) -> bool:
        """Check if Bedrock is configured."""
        return bool(self.aws_region and self.bedrock_model_id)

    def is_s3_configured(self) -> bool:
        """Check if S3 is configured."""
        return bool(self.aws_region and self.s3_bucket)

    def is_dynamodb_configured(self) -> bool:
        """Check if DynamoDB is configured."""
        return bool(self.aws_region and self.dynamodb_table)

# Global config instance
aws_config = AWSConfig()