output "bucket_name" {
  description = "The name of the S3 bucket owned by the CDK toolkit stack"
  value       = aws_s3_bucket.staging.id
}

output "bucket_domain_name" {
  description = "The domain name of the S3 bucket owned by the CDK toolkit stack"
  value       = aws_s3_bucket.staging.bucket_regional_domain_name
}

output "image_repository_name" {
  description = "The name of the ECR repository which hosts docker image assets"
  value       = aws_ecr_repository.assets.repository_url
}

output "bootstrap_version" {
  description = "The version of the bootstrap resources that are currently mastered in this stack"
  value       = local.cdk_bootstrap_version
}
