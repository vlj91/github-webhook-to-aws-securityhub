data "aws_iam_policy_document" "ci_ecr_push" {
  statement {
    effect = "Allow"

    actions = [
      "ecr:GetDownloadUrlForLayer",
      "ecr:BatchGetImage",
      "ecr:BatchCheckLayerAvailability",
      "ecr:PutImage",
      "ecr:InitiateLayerUpload",
      "ecr:UploadLayerPart",
      "ecr:CompleteLayerUpload"
    ]

    resources = [aws_ecr_repository.this.arn]
  }

  statement {
    effect = "Allow"
    actions = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }

  statement {
    effect = "Allow"
    actions = ["ssm:PutParameter"]
    resources = [aws_ssm_parameter.image_version.arn]
  }
}

data "aws_iam_policy_document" "ci_update_parameter_store" {
  statement {
    effect = "Allow"
    actions = ["ssm:PutParameter"]
    resources = [aws_ssm_parameter.image_version.arn]
  }
}

module "ci_iam_user" {
  source = "terraform-aws-modules/iam/aws//modules/iam-user"
  version = "~> 3.0"
  name = "github-webhook-to-securityhub-ci"
  create_iam_user_login_profile = false
}

resource "aws_ssm_parameter" "ci_access_key" {
  name = "/service/github-webhook-to-securityhub/iam_access_key"
  type = "SecureString"
  value = module.ci_iam_user.this_iam_access_key_id
}

resource "aws_ssm_parameter" "ci_secret_acccess_key" {
  name = "/service/github-webhook-to-securityhub/iam_secret_access_key"
  type = "SecureString"
  value = module.ci_iam_user.this_iam_access_key_secret
}

module "ci_iam_group" {
  source = "terraform-aws-modules/iam/aws//modules/iam-group-with-policies"
  version = "~> 3.0"
  name = "github-webhook-to-securityhub-ci"
  group_users = [module.ci_iam_user.this_iam_user_name]
  attach_iam_self_management_policy = false

  custom_group_policies = [
    {
      name = "ci_ecr_push"
      policy = data.aws_iam_policy_document.ci_ecr_push.json
    },
    {
      name = "ci_update_parameter_store"
      policy = data.aws_iam_policy_document.ci_update_parameter_store.json
    }
  ]
}