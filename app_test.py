
from dataclasses import dataclass
from unittest.mock import call
from botocore.stub import Stubber

from app import securityhub

import json
import pytest
import app

@pytest.fixture
def securityhub_stub():
  securityhub_stub = Stubber(securityhub)
  securityhub_stub.activate()
  yield securityhub_stub
  securityhub_stub.deactivate()

@pytest.fixture
def securityhub_successful_import():
  return {
    "ResponseMetadata": {
      "RequestId": "2cda4dc4-cca4-42e9-898b-e76efb4ba2f4",
      "HTTPStatusCode": 200,
      "HTTPHeaders": {
        "date": "Thu, 27 May 2021 08:36:01 GMT",
        "content-type": "application/json",
        "content-length": "54",
        "connection": "keep-alive",
        "x-amzn-requestid": "2cda4dc4-cca4-42e9-898b-e76efb4ba2f4",
        "x-amz-apigw-id": "f-r9rE7pywMFtqQ=",
        "x-amzn-trace-id": "Root=1-60af59f1-40276be638c707c4296e5051"
      },
      "RetryAttempts": 0
    },
    "FailedCount": 0,
    "SuccessCount": 1,
    "FailedFindings": []
  }

@pytest.fixture
def securityhub_successful_resolve():
  return {
    "ResponseMetadata": {
      "RequestId": "2cda4dc4-cca4-42e9-898b-e76efb4ba2f4",
      "HTTPStatusCode": 200,
      "HTTPHeaders": {
        "date": "Thu, 27 May 2021 08:36:01 GMT",
        "content-type": "application/json",
        "content-length": "54",
        "connection": "keep-alive",
        "x-amzn-requestid": "2cda4dc4-cca4-42e9-898b-e76efb4ba2f4",
        "x-amz-apigw-id": "f-r9rE7pywMFtqQ=",
        "x-amzn-trace-id": "Root=1-60af59f1-40276be638c707c4296e5051"
      },
      "RetryAttempts": 0
    },
    "ProcessedFindings": [
      {
        "Id": "576891938",
        "ProductArn": "arn:aws:securityhub:ap-southeast-2:123456789:product/123456789/default"
      }
    ],
    "UnprocessedFindings": []
  }

@pytest.fixture
def lambda_context():
    @dataclass
    class LambdaContext:
        function_name: str = "test"
        memory_limit_in_mb: int = 128
        invoked_function_arn: str = "arn:aws:lambda:eu-west-1:809313241:function:test"
        aws_request_id: str = "52fdfc07-2182-154f-163f-5f0f9a621d72"

    return LambdaContext()

@pytest.fixture
def create_event():
  return {
    "action": "create",
    "alert": {
      "id": 576891938,
      "affected_range": "< 4.3.1",
      "affected_package_name": "bootstrap",
      "external_reference": "https://nvd.nist.gov/vuln/detail/CVE-2019-8331",
      "external_identifier": "CVE-2019-8331",
      "ghsa_id": "GHSA-9v3m-8fp8-mj99",
      "created_at": "2021-04-06T09:43:28Z",
      "severity": "moderate",
      "fixed_in": "4.3.1"
    },
    "repository": {
      "id": 324689641,
      "name": "nrl",
      "full_name": "vlj91/nrl",
      "owner": {
        "login": "vlj91"
      }
    }
  }

@pytest.fixture
def dismiss_event():
  return {
    "action": "dismiss",
    "alert": {
      "id": 576891938,
      "affected_range": "< 4.3.1",
      "affected_package_name": "bootstrap",
      "external_reference": "https://nvd.nist.gov/vuln/detail/CVE-2019-8331",
      "external_identifier": "CVE-2019-8331",
      "ghsa_id": "GHSA-9v3m-8fp8-mj99",
      "created_at": "2021-04-06T09:43:28Z",
      "fixed_in": "4.3.1"
    },
    "repository": {
      "id": 324689641,
      "name": "nrl",
      "full_name": "vlj91/nrl",
    }
  }

@pytest.fixture
def resolve_event():
  return {
    "action": "resolve",
    "alert": {
      "id": 576891938,
      "affected_range": "< 4.3.1",
      "affected_package_name": "bootstrap",
      "external_reference": "https://nvd.nist.gov/vuln/detail/CVE-2019-8331",
      "external_identifier": "CVE-2019-8331",
      "ghsa_id": "GHSA-9v3m-8fp8-mj99",
      "created_at": "2021-04-06T09:43:28Z",
      "fixed_in": "4.3.1"
    },
    "repository": {
      "id": 324689641,
      "name": "nrl",
      "full_name": "vlj91/nrl",
    }
  }

@pytest.fixture
def invalid_event():
  return {
    "action": "invalid",
    "alert": {
      "id": 576891938,
      "affected_range": "< 4.3.1",
      "affected_package_name": "bootstrap",
      "external_reference": "https://nvd.nist.gov/vuln/detail/CVE-2019-8331",
      "external_identifier": "CVE-2019-8331",
      "ghsa_id": "GHSA-9v3m-8fp8-mj99",
      "created_at": "2021-04-06T09:43:28Z",
      "fixed_in": "4.3.1"
    },
    "repository": {
      "id": 324689641,
      "name": "nrl",
      "full_name": "vlj91/nrl",
    }
  }

def test_create_event(lambda_context, create_event, securityhub_successful_import, securityhub_stub):
  securityhub_stub.add_response(
    "batch_import_findings", securityhub_successful_import
  )

  event = {
    "body": json.dumps(create_event),
    "path": "/",
    "httpMethod": "POST",
    "requestContext": {
      "requestId": "c6af9ac6-7b61-11e6-9a41-93e8deadbeef"
    }
  }

  resp = app.lambda_handler(event, lambda_context)
  body = json.loads(resp['body'])

  assert body['message'] == 'Successfully imported finding'
  assert body['statusCode'] == 200
  assert resp['headers']['Content-Type'] == 'application/json'

def test_resolve_event(lambda_context, resolve_event, securityhub_successful_resolve, securityhub_stub):
  securityhub_stub.add_response(
    "batch_update_findings", securityhub_successful_resolve
  )

  event = {
    "body": json.dumps(resolve_event),
    "path": "/",
    "httpMethod": "POST",
    "requestContext": {
      "requestId": "c6af9ac6-7b61-11e6-9a41-93e8deadbeef"
    }
  }

  resp = app.lambda_handler(event, lambda_context)
  body = json.loads(resp['body'])

  assert body['message'] == 'Successfully resolved finding'
  assert body['statusCode'] == 200
  assert resp['headers']['Content-Type'] == 'application/json'

def test_invalid_method(lambda_context):
  event = {
    "path": "/",
    "httpMethod": "GET",
    "requestContext": {
      "requestId": "c6af9ac6-7b61-11e6-9a41-93e8deadbeef"
    }
  }

  resp = app.lambda_handler(event, lambda_context)
  assert resp['statusCode'] == 404
  assert resp['headers']['Content-Type'] == 'application/json'
