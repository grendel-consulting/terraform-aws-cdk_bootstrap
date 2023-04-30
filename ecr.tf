# tfsec:ignore:aws-ecr-repository-customer-key
resource "aws_ecr_repository" "assets" {
  name                 = local.has_custom_container_assets_repository_name == true ? var.container_assets_repository_name : "cdk-${var.qualifier}-container-assets-${data.aws_caller_identity.current.account_id}-${data.aws_region.current.name}"
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }
}

resource "aws_ecr_lifecycle_policy" "assets" {
  repository = aws_ecr_repository.assets.name

  policy = <<EOF
{
    "rules": [
        {
            "rulePriority": 1,
            "description": "Untagged images should not exist, but expire any older than one year",
            "selection": {
                "tagStatus": "untagged",
                "countType": "sinceImagePushed",
                "countUnit": "days",
                "countNumber": ${local.expiration_window_in_days}
            },
            "action": {
                "type": "expire"
            }
        }
    ]
}
EOF
}

data "aws_iam_policy_document" "container_assets" {
  statement {
    sid    = "LambdaECRImageRetrievalPolicy"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }

    actions = [
      "ecr:GetDownloadUrlForLayer",
      "ecr:BatchGetImage",
    ]

    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:aws:lambda:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:function:*"]
    }
  }
}

resource "aws_ecr_repository_policy" "container_assets" {
  repository = aws_ecr_repository.assets.name
  policy     = data.aws_iam_policy_document.container_assets.json
}
