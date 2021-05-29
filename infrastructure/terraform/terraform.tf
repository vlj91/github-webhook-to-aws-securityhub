# Manually created then imported
resource "aws_s3_bucket" "state" {
  bucket = "tf-state-github-webhook-to-aws-securityhub"
  acl = "private"

  server_side_encryption_configuration {
    rule {
      bucket_key_enabled = false

      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}

terraform {
  backend "s3" {
    bucket = "tf-state-github-webhook-to-aws-securityhub"
    region = "ap-southeast-2"
    key    = "service"
  }

  required_providers {
    aws = {
      source = "hashicorp/aws"
      version = "~> 3.0"
    }
  }
}

provider "aws" {
  region = "ap-southeast-2"

  default_tags {
    tags = {
      "service" = "github-webhook-to-securityhub"
    }
  }
}