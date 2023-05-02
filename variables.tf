variable "trusted_accounts" {
  type        = list(string)
  description = "List of AWS accounts that are trusted to publish assets and deploy stacks to this environment"
  default     = []
}

variable "trusted_accounts_for_lookup" {
  type        = list(string)
  description = "List of AWS accounts that are trusted to look up values in this environment"
  default     = []
}

variable "cloudformation_execution_policies" {
  type        = list(string)
  description = "List of the ManagedPolicy ARN(s) to attach to the CloudFormation deployment role"
  default     = []
}

variable "file_assets_bucket_name" {
  type        = string
  description = "Name of the S3 bucket used for file assets"
  default     = ""
}

variable "file_assets_bucket_kms_key_id" {
  type        = string
  description = "Empty to create a new key (default), 'AWS_MANAGED_KEY' to use a managed S3 key, or the ID/ARN of an existing key."
  default     = ""
}

variable "container_assets_repository_name" {
  type        = string
  description = "User-provided custom name to use for the container assets ECR repository"
  default     = ""
}

variable "qualifier" {
  type        = string
  description = "Identifier to distinguish multiple bootstrap stacks in the same environment"

  validation {
    condition     = can(regex("^[-_a-zA-Z0-9]+$", var.qualifier))
    error_message = "Qualifier must be an alphanumeric identifier of at most 10 characters"
  }
}

# variable "public_access_block_configuration" {
#   type        = bool
#   description = "Whether or not to enable S3 Staging Bucket Public Access Block Configuration"
#   default     = true
# }

variable "input_permissions_boundary" {
  type        = string
  description = "Whether or not to use either the CDK supplied or custom permissions boundary"
  default     = ""
}

variable "use_example_permissions_boundary" {
  type    = bool
  default = false
}

# variable "bootstrap_variant" {
#   type        = string
#   description = "Describe the provenance of the resources in this bootstrap stack. Change this when you customize the template. To prevent accidents, the CDK CLI will not overwrite bootstrap stacks with a different variant."
#   default     = "Grendel Consulting"
# }
