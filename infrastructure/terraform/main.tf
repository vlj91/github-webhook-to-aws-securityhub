data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

resource "aws_ssm_parameter" "image_version" {
  name = "/service/github-webhook-to-securityhub/image_version"
  type = "String"
  # set an initial version and ignore future changes
  value = "latest"

  lifecycle {
    ignore_changes = [value]
  }
}

# load the version back in as a data source to ensure we've always got the latest value
data "aws_ssm_parameter" "image_version" {
  name = aws_ssm_parameter.image_version.name
}

resource "aws_ecr_repository" "this" {
  name = "github-webhook-to-securityhub"

  image_scanning_configuration {
    scan_on_push = true
  }
}

data "aws_iam_policy_document" "function" {
  statement {
    effect = "Allow"
    actions = ["securityhub:BatchImportFindings"]
    resources = ["*"]
  }

  statement {
    effect = "Allow"
    actions = ["securityhub:BatchUpdateFindings"]
    resources = ["*"]
  }
}

module "function" {
  source = "terraform-aws-modules/lambda/aws"

  function_name      = "github-webhook-to-securityhub"
  description        = "Handles select GitHub webhooks, turning them into AWS SecurityHub findings"
  create_package     = false
  package_type       = "Image"
  image_uri          = "${aws_ecr_repository.this.repository_url}:${data.aws_ssm_parameter.image_version.value}"
  publish            = true
  attach_policy_json = true
  policy_json        = data.aws_iam_policy_document.function.json

  allowed_triggers = {
    APIGatewayPost = {
      service    = "apigateway"
      source_arn = "${module.api_gateway.apigatewayv2_api_execution_arn}/$default/POST/*"
    }
  }
}

resource "aws_cloudwatch_log_group" "access_logs" {
  name = "/aws/apigateway/github-webhook-to-securityhub"
}

module "api_gateway" {
  source                 = "terraform-aws-modules/apigateway-v2/aws"
  name                   = "github-webhook-to-securityhub"
  description            = "Handles GitHub webhooks"
  protocol_type          = "HTTP"
  create_api_domain_name = false

  cors_configuration = {
    allow_headers = ["accept", "content-type", "user-agent", "x-github-delivery", "x-github-event", "x-github-hook-id", "x-github-hook-installation-target-id", "x-github-hook-installation-target-type"]
    allow_methods = ["POST"]
    allow_origins = ["*"]
  }

  default_stage_access_log_destination_arn = aws_cloudwatch_log_group.access_logs.arn
  default_stage_access_log_format          = "$context.identity.sourceIp - - [$context.requestTime] \"$context.httpMethod $context.routeKey $context.protocol\" $context.status $context.responseLength $context.requestId $context.integrationErrorMessage"

  integrations = {
    "POST /" = {
      lambda_arn = module.function.lambda_function_arn
      payload_format_version = "2.0"
    }
  }
}