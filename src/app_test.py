
from dataclasses import dataclass
from unittest.mock import call
from botocore.stub import Stubber

from app import securityhub

import json
import pytest
import app
import requests

@pytest.fixture
def securityhub_stub():
  securityhub_stub = Stubber(securityhub)
  securityhub_stub.activate()
  yield securityhub_stub
  securityhub_stub.deactivate()

@pytest.fixture
def requests_stub():
  requests_stub = Stubber(requests)
  requests_stub.activate()
  yield requests_stub
  requests_stub.deactivate()

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
def redhat_cve_info():
  # Trimmed down payload containing the things we care about
  return {
    "threat_severity": "Moderate",
    "bugzilla": {
      "description": "CVE-2019-8331 bootstrap: XSS in the tooltip or popover data-template attribute",
      "id": "1686454",
      "url": "https://bugzilla.redhat.com/show_bug.cgi?id=1686454"
    },
    "cvss3": {
      "cvss3_base_score": "6.1",
      "cvss3_scoring_vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
      "status": "verified"
    },
    "details": [
      "In Bootstrap before 3.4.1 and 4.3.x before 4.3.1, XSS is possible in the tooltip or popover data-template attribute.",
      "A cross-site scripting vulnerability was discovered in bootstrap. If an attacker could control the data given to tooltip or popover, they could inject HTML or Javascript into the rendered page when tooltip or popover events fired."
    ],
    "statement": "Red Hat CloudForms 4.6 and newer versions include the vulnerable component, but there is no risk of exploitation since there is no possible vector to access the vulnerability. Older Red Hat CloudForms versions don't use the vulnerable component at all."
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
def invalid_action_event():
  return {
    "action": "invalid_action",
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
    "version": "2.0",
    "routeKey": "POST /",
    "body": json.dumps(create_event),
    "rawPath": "/",
    "requestContext": {
      "http": {
        "method": "POST",
        "path": "/default/"
      }
    },
    "requestId": "c6af9ac6-7b61-11e6-9a41-93e8deadbeef"
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
    "version": "2.0",
    "routeKey": "POST /",
    "body": json.dumps(resolve_event),
    "rawPath": "/",
    "requestContext": {
      "http": {
        "method": "POST",
        "path": "/default/"
      }
    },
    "requestId": "c6af9ac6-7b61-11e6-9a41-93e8deadbeef"
  }

  resp = app.lambda_handler(event, lambda_context)
  body = json.loads(resp['body'])

  assert body['message'] == 'Successfully resolved finding'
  assert body['statusCode'] == 200
  assert resp['headers']['Content-Type'] == 'application/json'

def test_invalid_action(lambda_context, invalid_action_event):
  event = {
    "version": "2.0",
    "routeKey": "POST /",
    "body": json.dumps(invalid_action_event),
    "rawPath": "/",
    "requestContext": {
      "http": {
        "method": "POST",
        "path": "/default/"
      }
    },
    "requestId": "c6af9ac6-7b61-11e6-9a41-93e8deadbeef"
  }

  resp = app.lambda_handler(event, lambda_context)
  body = json.loads(resp['body'])

  assert body['message'] == 'Invalid event type'
  assert resp['statusCode'] == 422
  assert resp['headers']['Content-Type'] == 'application/json'

def test_invalid_method(lambda_context):
  event = {
    "version": "2.0",
    "routeKey": "GET /",
    "rawPath": "/",
    "requestContext": {
      "http": {
        "method": "GET",
        "path": "/default/"
      }
    }
  }

  resp = app.lambda_handler(event, lambda_context)
  assert resp['statusCode'] == 404
  assert resp['headers']['Content-Type'] == 'application/json'

def test_invalid_path(lambda_context, create_event):
  event = {
    "version": "2.0",
    "routeKey": "POST /wrong_path",
    "body": json.dumps(create_event),
    "rawPath": "/wrong_path",
    "requestContext": {
      "http": {
        "method": "POST",
        "path": "/default/wrong_path"
      }
    },
    "requestId": "c6af9ac6-7b61-11e6-9a41-93e8deadbeef"
  }

  resp = app.lambda_handler(event, lambda_context)
  assert resp['statusCode'] == 404
  assert resp['headers']['Content-Type'] == 'application/json'

def test_get_severity_valid_payloads():
  assert app.get_severity('Low') == 'LOW'
  assert app.get_severity('Moderate') == 'MEDIUM'
  assert app.get_severity('High') == 'HIGH'
  assert app.get_severity('Critical') == 'CRITICAL'

def test_extra_cve_info_valid_cve(redhat_cve_info, requests_stub):
    requests_stub.add_response(
      "get", redhat_cve_info
    )

    cve_id = 'CVE-2019-8331'
    resp = extra_cve_info(cve_id)

    assert resp['Title'] == redhat_cve_info['bugzilla']['description']
    assert resp['Description'] == redhat_cve_info['details'][0]
    assert len(resp['Vulnerabilities']) == 1
    assert len(resp['Vulnerabilities'][0]['Cvss']) == 1
    assert len(resp['ReferenceUrls']) >= 1

def test_extra_cve_info_invalid_cve(requests_stub):
    requests_stub.add_response(
      "get", {}
    )

    cve_id = 'CVE-BLA-BLA'
    resp = extra_cve_info(cve_id)

    assert resp == {}
