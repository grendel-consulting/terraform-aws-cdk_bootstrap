resource "aws_iam_role" "file_publishing_role" {
  name               = "cdk-${var.qualifier}-file-publishing-role-${data.aws_caller_identity.current.account_id}-${data.aws_region.current.name}"
  assume_role_policy = data.aws_iam_policy_document.assume_role_policy.json

  tags = {
    "aws-cdk:bootstrap-role" = "file-publishing"
  }
}

resource "aws_iam_policy" "file_publishing_policy" {
  name   = "cdk-${var.qualifier}-file-publishing-role-default-policy-${data.aws_caller_identity.current.account_id}-${data.aws_region.current.name}"
  policy = data.aws_iam_policy_document.file_publishing_policy.json
}

# trivy:ignore:AVD-AWS-0057 - IAM Policy Document Uses Wildcarded Action
data "aws_iam_policy_document" "file_publishing_policy" {
  statement {
    sid       = "AllowFilePublishing"
    actions   = ["s3:GetObject*", "s3:GetBucket*", "s3:GetEncryptionConfiguration", "s3:List*", "s3:DeleteObject*", "s3:PutObject*", "s3:Abort*"]
    effect    = "Allow"
    resources = [aws_s3_bucket.staging.arn, "${aws_s3_bucket.staging.arn}/*"]
  }

  statement {
    sid       = "AllowUseOfKey"
    actions   = ["kms:Decrypt", "kms:DescribeKey", "kms:Encrypt", "kms:ReEncrypt*", "kms:GenerateDataKey*"]
    effect    = "Allow"
    resources = [local.create_new_key == true ? aws_kms_key.staging_key[0].arn : "arn:aws:kms:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:key/${var.file_assets_bucket_kms_key_id}"]
  }
}

resource "aws_iam_role_policy_attachment" "file_publishing_policy_attachment" {
  role       = aws_iam_role.file_publishing_role.name
  policy_arn = aws_iam_policy.file_publishing_policy.arn
}

resource "aws_iam_role" "image_publishing_role" {
  name               = "cdk-${var.qualifier}-image-publishing-role-${data.aws_caller_identity.current.account_id}-${data.aws_region.current.name}"
  assume_role_policy = data.aws_iam_policy_document.assume_role_policy.json

  tags = {
    "aws-cdk:bootstrap-role" = "image-publishing"
  }
}

resource "aws_iam_policy" "image_publishing_policy" {
  name   = "cdk-${var.qualifier}-image-publishing-role-default-policy-${data.aws_caller_identity.current.account_id}-${data.aws_region.current.name}"
  policy = data.aws_iam_policy_document.image_publishing_policy.json
}

# trivy:ignore:AVD-AWS-0057 - IAM Policy Document Uses Wildcarded Action
data "aws_iam_policy_document" "image_publishing_policy" {
  statement {
    sid       = "AllowImagePublishing"
    actions   = ["ecr:PutImage", "ecr:InitiateLayerUpload", "ecr:UploadLayerPart", "ecr:CompleteLayerUpload", "ecr:BatchCheckLayerAvailability", "ecr:DescribeRepositories", "ecr:DescribeImages", "ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"]
    effect    = "Allow"
    resources = [aws_ecr_repository.assets.arn]
  }

  statement {
    sid       = "AllowAuthorisation"
    actions   = ["ecr:GetAuthorizationToken"]
    effect    = "Allow"
    resources = ["*"]
  }
}

resource "aws_iam_role_policy_attachment" "image_publishing_policy_attachment" {
  role       = aws_iam_role.image_publishing_role.name
  policy_arn = aws_iam_policy.image_publishing_policy.arn
}

data "aws_iam_policy_document" "assume_role_policy" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = [data.aws_caller_identity.current.account_id]
    }

    dynamic "principals" {
      for_each = local.has_trusted_accounts ? { "k" : "v" } : {}
      content {
        type        = "AWS"
        identifiers = var.trusted_accounts
      }
    }
  }
}

resource "aws_iam_role" "lookup_role" {
  name                = "cdk-${var.qualifier}-lookup-role-${data.aws_caller_identity.current.account_id}-${data.aws_region.current.name}"
  assume_role_policy  = data.aws_iam_policy_document.assume_role_policy_with_lookups.json
  managed_policy_arns = ["arn:aws:iam::aws:policy/ReadOnlyAccess"]
  tags = {
    "aws-cdk:bootstrap-role" = "lookup"
  }
}

resource "aws_iam_policy" "lookup_policy" {
  name   = "cdk-${var.qualifier}-lookup-policy-${data.aws_caller_identity.current.account_id}-${data.aws_region.current.name}"
  policy = data.aws_iam_policy_document.lookup_policy.json
}

data "aws_iam_policy_document" "lookup_policy" {
  statement {
    sid       = "DontReadSecrets"
    actions   = ["kms:Decrypt"]
    effect    = "Deny"
    resources = ["*"]
  }
}

resource "aws_iam_role_policy_attachment" "lookup_policy_attachment" {
  role       = aws_iam_role.lookup_role.name
  policy_arn = aws_iam_policy.lookup_policy.arn
}

data "aws_iam_policy_document" "assume_role_policy_with_lookups" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = [data.aws_caller_identity.current.account_id]
    }

    dynamic "principals" {
      for_each = local.has_trusted_accounts ? { "k" : "v" } : {}
      content {
        type        = "AWS"
        identifiers = var.trusted_accounts
      }
    }

    dynamic "principals" {
      for_each = local.has_trusted_accounts_for_lookup ? { "k" : "v" } : {}
      content {
        type        = "AWS"
        identifiers = var.trusted_accounts_for_lookup
      }
    }
  }
}

resource "aws_iam_role" "deployment_action_role" {
  name               = "cdk-${var.qualifier}-deploy-role-${data.aws_caller_identity.current.account_id}-${data.aws_region.current.name}"
  assume_role_policy = data.aws_iam_policy_document.assume_role_policy.json

  tags = {
    "aws-cdk:bootstrap-role" = "deploy"
  }
}

resource "aws_iam_policy" "deployment_action_policy" {
  name   = "cdk-${var.qualifier}-deployment-action-policy-${data.aws_caller_identity.current.account_id}-${data.aws_region.current.name}"
  policy = data.aws_iam_policy_document.deployment_action_policy.json
}

# trivy:ignore:AVD-AWS-0057 - IAM Policy Document Uses Wildcarded Action
# trivy:ignore:AVD-AWS-0342 - IAM Policy Allows iam:PassRole Action
data "aws_iam_policy_document" "deployment_action_policy" {
  statement {
    sid       = "CloudFormationPermissions"
    actions   = ["cloudformation:CreateChangeSet", "cloudformation:DeleteChangeSet", "cloudformation:DescribeChangeSet", "cloudformation:DescribeStacks", "cloudformation:ExecuteChangeSet", "cloudformation:CreateStack", "cloudformation:UpdateStack"]
    effect    = "Allow"
    resources = ["*"]
  }

  statement {
    sid       = "PipelineCrossAccountArtifactsBucket"
    actions   = ["s3:GetObject*", "s3:GetBucket*", "s3:List*", "s3:Abort*", "s3:DeleteObject*", "s3:PutObject*"]
    effect    = "Allow"
    resources = ["*"]

    condition {
      test     = "StringNotEquals"
      variable = "s3:ResourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }

  dynamic "statement" {
    for_each = local.has_trusted_accounts ? { "k" : "v" } : {}
    content {
      sid       = "PipelineCrossAccountArtifactsKey"
      actions   = ["kms:Decrypt", "kms:DescribeKey", "kms:Encrypt", "kms:ReEncrypt*", "kms:GenerateDataKey*"]
      effect    = "Allow"
      resources = [for t in var.trusted_accounts : "arn:aws:kms:*:${t}:*"]

      condition {
        test     = "StringEquals"
        variable = "kms:ViaService"
        values   = ["s3.${data.aws_region.current.name}.amazonaws.com"]
      }
    }
  }

  statement {
    sid       = "PassRole"
    actions   = ["iam:PassRole"]
    effect    = "Allow"
    resources = [aws_iam_role.cloud_formation_execution_role.arn]
  }

  statement {
    sid       = "CliPermissions"
    actions   = ["cloudformation:DescribeStackEvents", "cloudformation:GetTemplate", "cloudformation:DeleteStack", "cloudformation:UpdateTerminationProtection", "sts:GetCallerIdentity", "cloudformation:GetTemplateSummary"]
    effect    = "Allow"
    resources = ["*"]
  }

  statement {
    sid       = "CliStagingBucket"
    actions   = ["s3:GetObject*", "s3:GetBucket*", "s3:List*"]
    effect    = "Allow"
    resources = [aws_s3_bucket.staging.arn, "${aws_s3_bucket.staging.arn}/*"]
  }

  statement {
    sid       = "ReadVersion"
    actions   = ["ssm:GetParameter"]
    effect    = "Allow"
    resources = [aws_ssm_parameter.cdk_bootstrap_version.arn]
  }
}


resource "aws_iam_role_policy_attachment" "deployment_action_policy_attachment" {
  role       = aws_iam_role.deployment_action_role.name
  policy_arn = aws_iam_policy.deployment_action_policy.arn
}

resource "aws_iam_role" "cloud_formation_execution_role" {
  name                 = "cdk-${var.qualifier}-cfn-exec-role-${data.aws_caller_identity.current.account_id}-${data.aws_region.current.name}"
  assume_role_policy   = data.aws_iam_policy_document.cloudformation_assume_role_policy.json
  managed_policy_arns  = local.has_cloudformation_execution_policies == true ? var.cloudformation_execution_policies : (local.has_trusted_accounts == true ? [] : ["arn:aws:iam::aws:policy/AdministratorAccess"])
  permissions_boundary = local.permissions_boundary_set == true ? aws_iam_policy.cdk_permissions_boundary[0].arn : null
}

data "aws_iam_policy_document" "cloudformation_assume_role_policy" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["cloudformation.amazonaws.com"]
    }
  }
}

resource "aws_iam_policy" "cdk_permissions_boundary" {
  count = local.should_create_permissions_boundary == true ? 1 : 0

  name        = "cdk-${var.qualifier}-permissions-boundary-${data.aws_caller_identity.current.account_id}-${data.aws_region.current.name}"
  description = "CDK Bootstrap Permissions Boundary"
  policy      = data.aws_iam_policy_document.cdk_permissions_boundary[count.index].json
  path        = "/"
}

# trivy:ignore:AVD-AWS-0057 - IAM Policy Document Uses Wildcarded Action
data "aws_iam_policy_document" "cdk_permissions_boundary" {
  count = local.should_create_permissions_boundary == true ? 1 : 0

  statement {
    sid       = "ExplicitAllowAll"
    actions   = ["*"]
    effect    = "Allow"
    resources = ["*"]
  }

  statement {
    sid       = "DenyAccessIfRequiredPermBoundaryIsNotBeingApplied"
    actions   = ["iam:CreateUser", "iam:CreateRole", "iam:PutRolePermissionsBoundary", "iam:PutUserPermissionsBoundary"]
    effect    = "Deny"
    resources = ["*"]

    condition {
      test     = "StringNotEquals"
      variable = "iam:PermissionsBoundary"
      values   = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:policy/cdk-${var.qualifier}-permissions-boundary-${data.aws_caller_identity.current.account_id}-${data.aws_region.current.name}"]
    }
  }

  statement {
    sid       = "DenyPermBoundaryIAMPolicyAlteration"
    actions   = ["iam:CreatePolicyVersion", "iam:DeletePolicy", "iam:DeletePolicyVersion", "iam:SetDefaultPolicyVersion"]
    effect    = "Deny"
    resources = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:policy/cdk-${var.qualifier}-permissions-boundary-${data.aws_caller_identity.current.account_id}${data.aws_region.current.name}"]
  }

  statement {
    sid       = "DenyRemovalOfPermBoundaryFromAnyUserOrRole"
    actions   = ["iam:DeleteUserPermissionsBoundary", "iam:DeleteRolePermissionsBoundary"]
    effect    = "Deny"
    resources = ["*"]
  }
}
