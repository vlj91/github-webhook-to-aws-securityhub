from aws_lambda_powertools import Logger, Metrics
from aws_lambda_powertools.logging import correlation_paths
from aws_lambda_powertools.metrics import MetricUnit
from aws_lambda_powertools.event_handler.api_gateway import ApiGatewayResolver, Response
from datetime import datetime

import boto3
import json
import os

app = ApiGatewayResolver()
logger = Logger(service="github-webhook")
metrics = Metrics(service="github-webhook", namespace="service")
securityhub = boto3.client('securityhub')

AWS_ACCOUNT_ID = os.environ.get('AWS_ACCOUNT_ID', '123456789')
AWS_REGION = os.environ.get('AWS_REGION', 'ap-southeast-2')

severity_levels = {
  'low': 'LOW',
  'moderate': 'MEDIUM',
  'high': 'HIGH',
  'critical': 'CRITICAL'  
}

def create_finding(payload):
  repo_name = payload['repository']['name']
  repo_owner = payload['repository']['owner']['login']
  package_name = payload['alert']['affected_package_name']
  cve_id = payload['alert']['external_identifier']
  fixed_in = payload['alert']['fixed_in']
  severity = payload['alert']['severity']
  github_alert_id = payload['alert']['id']

  logger.info("Creating finding", extra=payload)
  metrics.add_metric(name="finding_created", unit=MetricUnit.Count, value=1)

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
            'Id': str(github_alert_id),
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
