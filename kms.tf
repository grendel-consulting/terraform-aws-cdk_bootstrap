# tfsec:ignore:aws-kms-auto-rotate-keys
resource "aws_kms_key" "staging_key" {
  count = local.create_new_key ? 1 : 0

  description = "CDK Bootstrap Staging Bucket"
  policy      = data.aws_iam_policy_document.staging_key[count.index].json
}

resource "aws_kms_alias" "cdk_assets_key" {
  count = local.create_new_key ? 1 : 0

  name          = "alias/cdk-${var.qualifier}-assets-key"
  target_key_id = aws_kms_key.staging_key[count.index].key_id
}

data "aws_iam_policy_document" "staging_key" {
  count = local.create_new_key ? 1 : 0

  statement {
    sid    = "AllowAccount"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = [data.aws_caller_identity.current.account_id]
    }

    actions = [
      "kms:Create*",
      "kms:Describe*",
      "kms:Enable*",
      "kms:List*",
      "kms:Put*",
      "kms:Update*",
      "kms:Revoke*",
      "kms:Disable*",
      "kms:Get*",
      "kms:Delete*",
      "kms:ScheduleKeyDeletion",
      "kms:CancelKeyDeletion",
      "kms:GenerateDataKey",
      "kms:TagResource",
      "kms:UntagResource",
    ]

    resources = ["*"]
  }

  statement {
    sid    = "AllowLocalService"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    actions = [
      "kms:Decrypt",
      "kms:DescribeKey",
      "kms:Encrypt",
      "kms:GenerateDataKey*",
      "kms:ReEncrypt*",
    ]

    condition {
      test     = "StringEquals"
      variable = "kms:CallerAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.${data.aws_region.current.name}.amazonaws.com"]
    }

    resources = ["*"]
  }

  statement {
    sid    = "AllowFilePublishingRole"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.file_publishing_role.arn]
    }

    actions = [
      "kms:Decrypt",
      "kms:DescribeKey",
      "kms:Encrypt",
      "kms:GenerateDataKey*",
      "kms:ReEncrypt*",
    ]

    resources = ["*"]
  }
}
