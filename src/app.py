from aws_lambda_powertools import Logger, Metrics
from aws_lambda_powertools.logging import correlation_paths
from aws_lambda_powertools.metrics import MetricUnit
from aws_lambda_powertools.event_handler.api_gateway import ApiGatewayResolver, ProxyEventType, Response
from datetime import datetime

import boto3
import json
import os
import requests

app = ApiGatewayResolver(proxy_type=ProxyEventType.APIGatewayProxyEventV2)
logger = Logger(service="github-webhook")
metrics = Metrics(service="github-webhook", namespace="service")
securityhub = boto3.client('securityhub')

AWS_ACCOUNT_ID = os.environ.get('AWS_ACCOUNT_ID', '123456789')
AWS_REGION = os.environ.get('AWS_REGION', 'ap-southeast-2')

severity_levels = {
  'Low': 'LOW',
  'Moderate': 'MEDIUM',
  'High': 'HIGH',
  'Critical': 'CRITICAL'  
}

def cve_info(id):
  resp = requests.get('https://access.redhat.com/labs/securitydataapi/cve/%s' % id)
  if resp.ok:
    return resp.json()

def resolve_finding(payload):
  github_alert_id = payload['alert']['id']

  resp = securityhub.batch_update_findings(
    FindingIdentifiers=[
      {
        'Id': str(github_alert_id),
        'ProductArn': 'arn:aws:securityhub:%s:%s:product/%s/default' % (AWS_REGION, AWS_ACCOUNT_ID, AWS_ACCOUNT_ID),
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
  repo_name = payload['repository']['name']
  repo_owner = payload['repository']['owner']['login']
  package_name = payload['alert']['affected_package_name']
  cve_id = payload['alert']['external_identifier']
  fixed_in = payload['alert']['fixed_in']
  github_alert_id = payload['alert']['id']
  info = cve_info(cve_id)
  severity = info['threat_severity']

  logger.info("Creating finding", extra=payload)

  resp = securityhub.batch_import_findings(
    Findings=[
      {
        'SchemaVersion': '2018-10-08',
        'AwsAccountId': AWS_ACCOUNT_ID,
        'CreatedAt': datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        'UpdatedAt': datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        'Title': '%s affected by %s' % (package_name, cve_id),
        'Description': '%s package %s affected by %s, fixed in %s' % (repo_name, package_name, cve_id, fixed_in),
        'GeneratorId': 'github',
        'Id': str(github_alert_id),
        'ProductArn': 'arn:aws:securityhub:%s:%s:product/%s/default' % (AWS_REGION, AWS_ACCOUNT_ID, AWS_ACCOUNT_ID),
        'Severity': {
          'Label': severity_levels.get(severity)
        },
        'FindingProviderFields': {
          'Severity': {
            'Label': severity_levels.get(severity)
          },
          'Types': [
            'Software and Configuration Checks/Vulnerabilities/CVE'
          ]
        },
        'Resources': [
          {
            'Type': 'Other',
            'Id': payload['repository']['full_name'],
            'Details': {
              'Other': {
                'github.com/repository.name': repo_name,
                'github.com/repository.owner': repo_owner
              }
            }
          }
        ]
      }
    ]
  )

  logger.info(json.dumps(resp))
  if resp['SuccessCount'] >= 1:
    metrics.add_metric(name="findings_created",
                       unit=MetricUnit.Count,
                       value=resp['SuccessCount']
    )

    return { 
      "message": "Successfully imported finding",
      "statusCode": resp['ResponseMetadata']['HTTPStatusCode']
    }
  else:
    metrics.add_metric(name="failed_creations",
                       unit=MetricUnit.Count,
                       value=resp['FailedCount']
    )

    return {
      "message": "Failed to import finding",
      "statusCode": resp['ResponseMetadata']['HTTPStatusCode']
    }

@app.post("/")
def process():
  action = app.current_event.json_body['action']
  if action == 'create':
    return create_finding(app.current_event.json_body)
  elif action == 'resolve':
    return resolve_finding(app.current_event.json_body)
  else:
    return Response(
      status_code=422,
      content_type="application/json",
      body=json.dumps({"message": "Invalid event type"})
    )

@metrics.log_metrics
@logger.inject_lambda_context(correlation_id_path=correlation_paths.API_GATEWAY_REST)
def lambda_handler(event, context):
  return app.resolve(event, context)
