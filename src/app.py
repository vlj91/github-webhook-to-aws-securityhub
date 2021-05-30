from aws_lambda_powertools import Logger, Metrics
from aws_lambda_powertools.logging import correlation_paths
from aws_lambda_powertools.metrics import MetricUnit
from aws_lambda_powertools.event_handler.api_gateway import ApiGatewayResolver, ProxyEventType, Response
from datetime import datetime

import boto3
import json
import os
import requests


aws_account_id = os.environ.get('AWS_ACCOUNT_ID', '123456789')
aws_region = os.environ.get('AWS_REGION', 'ap-southeast-2')
app = ApiGatewayResolver(proxy_type=ProxyEventType.APIGatewayProxyEventV2)
logger = Logger(service="github-webhook")
metrics = Metrics(service="github-webhook", namespace="service")
securityhub = boto3.client('securityhub', region_name=aws_region)

# Return the severity level using the payloads from GitHub and RedHat
def get_severity(level):
  levels = {
    'low': 'LOW',
    'moderate': 'MEDIUM',
    'high': 'HIGH',
    'critical': 'CRITICAL'
  }

  return levels[level.lower()]

def cve_info(payload):
  resp = requests.get('https://access.redhat.com/labs/securitydataapi/cve/%s' % payload['alert']['external_identifier'])

  if resp.ok:
    body = resp.json()

    return {
      'Title': body['bugzilla']['description'],
      'Description': body['details'][0],
      'Severity': { 'Label': body['threat_severity'] },
      'FindingProviderFields': {
        'Severity': { 'Label': body['threat_severity'] },
        'Types': ['Software and Configuration Checks/Vulnerabilities/CVE']
      },
      'Vulnerabilities': [{
        'Cvss': [{
          'BaseScore': float(body['cvss3']['cvss3_base_score']),
          'BaseVector': body['cvss3']['cvss3_scoring_vector']
        }],
        'Id': body['bugzilla']['id'],
        'ReferenceUrls': [body['bugzilla']['url']]
      }]
    }
  else:
    return {}


def resolve_finding(payload):
  github_alert_id = payload['alert']['id']

  resp = securityhub.batch_update_findings(
    FindingIdentifiers=[
      {
        'Id': str(github_alert_id),
        'ProductArn': 'arn:aws:securityhub:%s:%s:product/%s/default' % (aws_region, aws_account_id, aws_account_id),
      }
    ],
    Note={
      'Text': 'Finding resolved',
      'UpdatedBy': 'github-webhook'
    },
    Workflow={
      'Status': 'RESOLVED'
    }
  )

  if len(resp['ProcessedFindings']) >= 1:
    metrics.add_metric(name="findings_resolved",
                       unit=MetricUnit.Count,
                       value=len(resp['ProcessedFindings'])
    )

    return {
      "message": "Successfully resolved finding",
      "statusCode": resp['ResponseMetadata']['HTTPStatusCode']
    }
  else:
    metrics.add_metric(name="failed_resolve",
                       unit=MetricUnit.Count,
                       value=len(resp['UnprocessedFindings'])
    )

    return {
      "message": "Failed to resolve finding",
      "statusCode": resp['ResponseMetadata']['HTTPStatusCode']
    }

def create_finding(payload):
  # Set some of these as vars as they get reused a few times
  repo_name = payload['repository']['name']
  repo_owner = payload['repository']['owner']['login']
  package_name = payload['alert']['affected_package_name']
  cve_id = payload['alert']['external_identifier']
  fixed_in = payload['alert']['fixed_in']
  github_alert_id = payload['alert']['id']
  redhat_info = cve_info(payload)

  findings = [{
    'SchemaVersion': '2018-10-08',
    'AwsAccountId': aws_account_id,
    'CreatedAt': datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
    'UpdatedAt': datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
    'GeneratorId': 'github',
    'Id': str(payload['alert']['id']),
    'ProductArn': 'arn:aws:securityhub:%s:%s:product/%s/default' % (aws_region, aws_account_id, aws_account_id),
    'Title': '%s %s' % (payload['alert']['affected_package_name'], payload['alert']['fixed_in']),
    'Description': payload['alert']['affected_package_name'],
    'Resources': [{
      'Type': 'Other',
      'Id': '%s/%s/%s' % (repo_name, package_name, cve_id),
      'Region': aws_region,
      'Details': {
        'Other': {
          'github.com/repository.name': payload['repository']['name'],
          'github.com/repository.owner': payload['repository']['owner']['login']
        }
      }
    }]
  }]

  logger.info("Attempting to import finding", extra=findings[0])
  resp = securityhub.batch_import_findings(Findings=findings)
  if resp['SuccessCount'] >= 1:
    logger.info("Successfully imported finding", extra=findings[0])
    metrics.add_metric(name="create_success",
                       unit=MetricUnit.Count,
                       value=resp['SuccessCount']
    )

    return { 
      "message": "Successfully imported finding",
      "statusCode": resp['ResponseMetadata']['HTTPStatusCode']
    }
  else:
    logger.info("Failed to import finding", extra=findings[0])
    metrics.add_metric(name="create_failure",
                       unit=MetricUnit.Count,
                       value=resp['FailedCount']
    )

    return {
      "message": "Failed to import finding",
      "statusCode": resp['ResponseMetadata']['HTTPStatusCode']
    }

# TODO: verify github signature
@app.post("/")
def process():
  action = app.current_event.json_body['action']
  if action == 'create':
    metrics.add_metric(name="create_event", unit=MetricUnit.Count, value=1)
    return create_finding(app.current_event.json_body)
  elif action == 'resolve':
    metrics.add_metric(name="resolve_event", unit=MetricUnit.Count, value=1)
    return resolve_finding(app.current_event.json_body)
  else:
    metrics.add_metric(name="invalid_event", unit=MetricUnit.Count, value=1)
    return Response(
      status_code=422,
      content_type="application/json",
      body=json.dumps({"message": "Invalid event type"})
    )

@metrics.log_metrics(raise_on_empty_metrics=False)
@logger.inject_lambda_context(correlation_id_path=correlation_paths.API_GATEWAY_REST)
def lambda_handler(event, context):
  return app.resolve(event, context)
