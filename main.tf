# Enabling the contract between CDK and the Bootstrap stack, this resource must
# be specifically named and have well-known outputs.
#
# See: https://docs.aws.amazon.com/cdk/v2/guide/bootstrapping.html
#
# Our conditional null resource is a hack to prevent the stack from being deleted.
#
resource "aws_cloudformation_stack" "bootstrap" {
  name = "CDKToolkit"
  template_body = jsonencode({
    Conditions = {
      Never = {
        "Fn::Equals" = [
          "Never",
          "Ever"
        ]
      }
    }
    Resources = {
      NonResource = {
        Type      = "Custom::NullResource"
        Condition = "Never"
      }
    }

    Outputs = {
      BucketName = {
        Value       = aws_s3_bucket.staging.id
        Description = "The name of the S3 bucket owned by the CDK toolkit stack"
      }
      BucketDomainName = {
        Value       = aws_s3_bucket.staging.bucket_regional_domain_name
        Description = "The domain name of the S3 bucket owned by the CDK toolkit stack"
      }
      FileAssetKeyArn = {
        Value       = local.create_new_key ? aws_kms_key.staging_key[0].arn : var.file_assets_bucket_kms_key_id
        Description = "The ARN of the KMS key used to encrypt the asset bucket (deprecated)"
        Export = {
          Name = "CdkBootstrap-${var.qualifier}-FileAssetKeyArn"
        }
      }
      ImageRepositoryName = {
        Value       = aws_ecr_repository.assets.repository_url
        Description = "The name of the ECR repository which hosts docker image assets"
      }
      BootstrapVersion = {
        Value       = aws_ssm_parameter.cdk_bootstrap_version.value
        Description = "The version of the bootstrap resources that are currently mastered in this stack"
      }
    }
  })
}
