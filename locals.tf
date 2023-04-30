locals {
  has_trusted_accounts                        = length(var.trusted_accounts) > 0
  has_trusted_accounts_for_lookup             = length(var.trusted_accounts_for_lookup) > 0
  has_cloudformation_execution_policies       = length(var.cloudformation_execution_policies) > 0
  has_custom_file_assets_bucket_name          = var.file_assets_bucket_name != ""
  create_new_key                              = var.file_assets_bucket_kms_key_id == ""
  use_managed_key                             = var.file_assets_bucket_kms_key_id == "AWS_MANAGED_KEY"
  should_create_permissions_boundary          = var.use_example_permissions_boundary == true
  permissions_boundary_set                    = var.input_permissions_boundary != ""
  has_custom_container_assets_repository_name = var.container_assets_repository_name != ""
  # use_public_access_block_configuration       = var.public_access_block_configuration == true

  expiration_window_in_days = 365
  cdk_bootstrap_version     = 17
}
