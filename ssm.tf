resource "aws_ssm_parameter" "cdk_bootstrap_version" {
  name  = "/cdk-bootstrap/${var.qualifier}/version"
  type  = "String"
  value = local.cdk_bootstrap_version
}
