# CDK Bootstrap
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/grendel-consulting/terraform-aws-cdk_bootstrap/badge)](https://scorecard.dev/viewer/?uri=github.com/grendel-consulting/terraform-aws-cdk_bootstrap)

Re-implementation of the CDK bootstrapping CloudFormation into a Terraform module, for easy use with AWS Account Factory for Terraform.

## Context

Before deploying resources using AWS CDK you must [bootstrap](https://docs.aws.amazon.com/cdk/v2/guide/bootstrapping.html) each environment, i.e. each combination of AWS Account _and_ Region you wish to deploy to. Out of the box this can be achieved with the `cdk bootstrap` command, which manifests as a CloudFormation Stack. When using AWS Control Tower with the AWS Account Factory for Terraform, a Terraform-based approach fits better.

## Provenance

By default, CDK allows for multiple CDK boostrapping stacks in th same environment, via the `qualifier` parameter, which acts as a namespace.

## Version

Over time the CDK bootstrap stack may evolve; this implementation is based on the most recent, version **17**, and the raw CloudFormation captured from running `cdk bootstrap --show-template > cloudformation\bootstrap.yaml` is versioned in this repository.
