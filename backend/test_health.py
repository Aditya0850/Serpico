"""Tests for the /health endpoint with AWS dependency checks."""

import os
import json
import sys
from unittest.mock import patch, MagicMock, AsyncMock
from starlette.testclient import TestClient

# Set development mode BEFORE importing app
os.environ["ENV"] = "development"

# Clear any cached modules
for mod in list(sys.modules.keys()):
    if mod.startswith("main") or mod.startswith("config"):
        del sys.modules[mod]

from main import app

client = TestClient(app)


def test_health_development_mode_no_aws():
    """Test /health in development mode without AWS configuration."""
    response = client.get("/health")
    assert response.status_code == 200

    data = response.json()
    assert data["status"] == "healthy"
    assert data["mode"] == "development"
    assert data["dependencies"]["dynamodb"] == "not_configured"
    assert data["dependencies"]["s3"] == "not_configured"
    assert data["dependencies"]["bedrock"] == "not_configured"

    # Ensure no sensitive data is exposed
    assert "AWS_REGION" not in json.dumps(data)
    assert "DYNAMODB_TABLE" not in json.dumps(data)
    assert "S3_BUCKET" not in json.dumps(data)
    assert "BEDROCK_MODEL_ID" not in json.dumps(data)


def test_health_no_sensitive_data_in_response():
    """Verify no credentials, ARNs, or infrastructure details leak in response."""
    response = client.get("/health")
    data = response.json()

    response_str = json.dumps(data)
    # Check for common sensitive patterns
    forbidden = [
        "arn:aws",
        "access_key",
        "secret_key",
        "token",
        "credential",
        "us-east-1",
        "trace-investigations",
        "trace-evidence",
        "anthropic.claude"
    ]
    for forbidden_str in forbidden:
        assert forbidden_str.lower() not in response_str.lower()


# Unit tests for health check helper functions
import asyncio


@patch("main.aws_config")
def test_check_dynamodb_healthy(mock_aws_config):
    """Test DynamoDB health check when configured and healthy."""
    from main import check_dynamodb_health

    mock_aws_config.is_dynamodb_configured.return_value = True
    mock_aws_config.aws_region = "us-east-1"
    mock_aws_config.dynamodb_table = "trace-investigations"

    with patch("boto3.resource") as mock_resource:
        mock_table = MagicMock()
        mock_table.table_status = "ACTIVE"
        mock_resource.return_value.Table.return_value = mock_table

        result = asyncio.run(check_dynamodb_health())
        assert result == "healthy"


@patch("main.aws_config")
def test_check_dynamodb_not_configured(mock_aws_config):
    """Test DynamoDB health check when not configured."""
    from main import check_dynamodb_health

    mock_aws_config.is_dynamodb_configured.return_value = False

    result = asyncio.run(check_dynamodb_health())
    assert result == "not_configured"


@patch("main.aws_config")
def test_check_dynamodb_degraded(mock_aws_config):
    """Test DynamoDB health check when configured but connection fails."""
    from main import check_dynamodb_health

    mock_aws_config.is_dynamodb_configured.return_value = True
    mock_aws_config.aws_region = "us-east-1"
    mock_aws_config.dynamodb_table = "trace-investigations"

    with patch("boto3.resource") as mock_resource:
        mock_resource.side_effect = Exception("Connection failed")

        result = asyncio.run(check_dynamodb_health())
        assert result == "degraded"


@patch("main.aws_config")
def test_check_s3_healthy(mock_aws_config):
    """Test S3 health check when configured and healthy."""
    from main import check_s3_health

    mock_aws_config.is_s3_configured.return_value = True
    mock_aws_config.aws_region = "us-east-1"
    mock_aws_config.s3_bucket = "trace-evidence"

    with patch("boto3.client") as mock_client:
        mock_client.return_value.head_bucket.return_value = {}

        result = asyncio.run(check_s3_health())
        assert result == "healthy"


@patch("main.aws_config")
def test_check_s3_not_configured(mock_aws_config):
    """Test S3 health check when not configured."""
    from main import check_s3_health

    mock_aws_config.is_s3_configured.return_value = False

    result = asyncio.run(check_s3_health())
    assert result == "not_configured"


@patch("main.aws_config")
def test_check_s3_degraded(mock_aws_config):
    """Test S3 health check when configured but connection fails."""
    from main import check_s3_health

    mock_aws_config.is_s3_configured.return_value = True
    mock_aws_config.aws_region = "us-east-1"
    mock_aws_config.s3_bucket = "trace-evidence"

    with patch("boto3.client") as mock_client:
        mock_client.side_effect = Exception("Connection failed")

        result = asyncio.run(check_s3_health())
        assert result == "degraded"


@patch("main.aws_config")
def test_check_bedrock_configured(mock_aws_config):
    """Test Bedrock health check when configured."""
    from main import check_bedrock_health

    mock_aws_config.is_bedrock_configured.return_value = True

    result = asyncio.run(check_bedrock_health())
    assert result == "configured"


@patch("main.aws_config")
def test_check_bedrock_not_configured(mock_aws_config):
    """Test Bedrock health check when not configured."""
    from main import check_bedrock_health

    mock_aws_config.is_bedrock_configured.return_value = False

    result = asyncio.run(check_bedrock_health())
    assert result == "not_configured"


if __name__ == "__main__":
    # Run unit tests directly
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))