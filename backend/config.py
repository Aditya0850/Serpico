import os
from typing import Optional
from dataclasses import dataclass

@dataclass
class ConfigValidationResult:
    """Result of configuration validation."""
    is_valid: bool
    service: str
    missing_vars: list[str]
    message: str

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

    def validate_for_dynamodb(self, is_development: bool = False) -> ConfigValidationResult:
        """Validate configuration for DynamoDB usage."""
        if is_development:
            return ConfigValidationResult(
                is_valid=True,
                service="DynamoDB",
                missing_vars=[],
                message="Development mode: DynamoDB optional"
            )

        missing = []
        if not self.aws_region:
            missing.append("AWS_REGION")
        if not self.dynamodb_table:
            missing.append("DYNAMODB_TABLE")

        return ConfigValidationResult(
            is_valid=len(missing) == 0,
            service="DynamoDB",
            missing_vars=missing,
            message=f"DynamoDB requires: {', '.join(missing)}" if missing else "DynamoDB configured"
        )

    def validate_for_s3(self, is_development: bool = False) -> ConfigValidationResult:
        """Validate configuration for S3 usage."""
        if not self.s3_bucket:
            # S3 is optional - not configured is valid
            return ConfigValidationResult(
                is_valid=True,
                service="S3",
                missing_vars=[],
                message="S3 not configured (optional)"
            )

        missing = []
        if not self.aws_region:
            missing.append("AWS_REGION")

        return ConfigValidationResult(
            is_valid=len(missing) == 0,
            service="S3",
            missing_vars=missing,
            message=f"S3 requires: {', '.join(missing)}" if missing else "S3 configured"
        )

    def validate_for_bedrock(self, is_development: bool = False) -> ConfigValidationResult:
        """Validate configuration for Bedrock usage."""
        if not self.bedrock_model_id:
            # Bedrock is optional - not configured is valid
            return ConfigValidationResult(
                is_valid=True,
                service="Bedrock",
                missing_vars=[],
                message="Bedrock not configured (optional)"
            )

        missing = []
        if not self.aws_region:
            missing.append("AWS_REGION")

        return ConfigValidationResult(
            is_valid=len(missing) == 0,
            service="Bedrock",
            missing_vars=missing,
            message=f"Bedrock requires: {', '.join(missing)}" if missing else "Bedrock configured"
        )

    def validate_all(self, is_development: bool = False) -> dict[str, ConfigValidationResult]:
        """Validate all AWS service configurations."""
        return {
            "dynamodb": self.validate_for_dynamodb(is_development),
            "s3": self.validate_for_s3(is_development),
            "bedrock": self.validate_for_bedrock(is_development)
        }

# Global config instance
aws_config = AWSConfig()