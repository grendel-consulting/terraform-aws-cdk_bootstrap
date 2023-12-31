# trivy:ignore:AVD-AWS-0086 - No Public Access Block So Not Blocking Public Access ACLs
# trivy:ignore:AVD-AWS-0087 - No Public Access Block So Not Blocking Public Policies
# trivy:ignore:AVD-AWS-0089 - Bucket Has Logging Disabled
# trivy:ignore:AVD-AWS-0091 - No Public Access Block So Not Ignoring Public ACLs
# trivy:ignore:AVD-AWS-0093 - No Public Access Block So Not Restricing Public Buckets
# trivy:ignore:AVD-AWS-0094 - Bucket Does Not Have A Corresponding Public Access Block
resource "aws_s3_bucket" "staging" {
  bucket = local.has_custom_file_assets_bucket_name == true ? var.file_assets_bucket_name : "cdk-${var.qualifier}-assets-${data.aws_caller_identity.current.account_id}-${data.aws_region.current.name}"

  # Since 2023-04-06, all new buckets are private by default
  # We can omit public access block and acl configuration

  tags = {
    Environment = "Production"
  }
}

data "aws_iam_policy_document" "staging_assets" {
  statement {
    sid    = "AllowSSLRequestsOnly"
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions = [
      "s3:*",
    ]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }

    resources = [
      aws_s3_bucket.staging.arn,
      "${aws_s3_bucket.staging.arn}/*",
    ]
  }
}

resource "aws_s3_bucket_policy" "staging_assets" {
  bucket = aws_s3_bucket.staging.id
  policy = data.aws_iam_policy_document.staging_assets.json
}


resource "aws_s3_bucket_server_side_encryption_configuration" "staging" {
  bucket = aws_s3_bucket.staging.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = local.create_new_key == true ? aws_kms_key.staging_key[0].id : (local.use_managed_key == true ? "aws/s3" : var.file_assets_bucket_kms_key_id)
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_versioning" "staging" {
  bucket = aws_s3_bucket.staging.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "staging" {
  depends_on = [aws_s3_bucket_versioning.staging]
  bucket     = aws_s3_bucket.staging.id

  rule {
    id     = "CleanUpOldVersions"
    status = "Enabled"

    noncurrent_version_expiration {
      noncurrent_days = local.expiration_window_in_days
    }
  }
}
