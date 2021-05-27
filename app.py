from aws_lambda_powertools import Logger, Metrics
from aws_lambda_powertools.logging import correlation_paths
from aws_lambda_powertools.event_handler.api_gateway import ApiGatewayResolver, Response


import boto3
import json
import os

app = ApiGatewayResolver()
logger = Logger(service="github-webhook")
metrics = Metrics(service="github-webhook", namespace="service")
securityhub = boto3.client('securityhub')

@metrics.log_metrics
@logger.inject_lambda_context(correlation_id_path=correlation_paths.API_GATEWAY_REST)
def lambda_handler(event, context):
  return app.resolve(event, context)
