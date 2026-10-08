# ------------------------------------------------------------------------------
# AWS Organizations — Multi-Account Structure
# ------------------------------------------------------------------------------
# Creates an Organization with an OU hierarchy that follows the AWS Security
# Reference Architecture (SRA). The management account owns the org; workloads,
# security tooling, and sandboxes each get their own OU so SCPs and RCPs can
# be scoped precisely.
#
# Why this structure matters:
# - Security OU gets the strictest SCPs (no one disables GuardDuty/CloudTrail)
# - Workloads OU gets environment-appropriate controls (deny unapproved regions)
# - Sandbox OU allows experimentation with spend guardrails
# ------------------------------------------------------------------------------

resource "aws_organizations_organization" "org" {
  aws_service_access_principals = [
    "cloudtrail.amazonaws.com",
    "config.amazonaws.com",
    "guardduty.amazonaws.com",
    "securityhub.amazonaws.com",
    "sso.amazonaws.com",
    "access-analyzer.amazonaws.com",
  ]

  enabled_policy_types = [
    "SERVICE_CONTROL_POLICY",
    "RESOURCE_CONTROL_POLICY",
    "TAG_POLICY",
  ]

  feature_set = "ALL"
}

# ------------------------------------------------------------------------------
# Organizational Units
# ------------------------------------------------------------------------------

resource "aws_organizations_organizational_unit" "security" {
  name      = "Security"
  parent_id = aws_organizations_organization.org.roots[0].id

  # Houses: log archive account, security tooling account (GuardDuty admin,
  # Security Hub admin, CloudTrail org trail destination)
}

resource "aws_organizations_organizational_unit" "workloads" {
  name      = "Workloads"
  parent_id = aws_organizations_organization.org.roots[0].id
}

resource "aws_organizations_organizational_unit" "workloads_prod" {
  name      = "Production"
  parent_id = aws_organizations_organizational_unit.workloads.id
}

resource "aws_organizations_organizational_unit" "workloads_dev" {
  name      = "Development"
  parent_id = aws_organizations_organizational_unit.workloads.id
}

resource "aws_organizations_organizational_unit" "sandbox" {
  name      = "Sandbox"
  parent_id = aws_organizations_organization.org.roots[0].id

  # Loose controls but strict spend limits. Used for learning and experimentation.
}

# ------------------------------------------------------------------------------
# Outputs — other modules reference these OU IDs to attach policies
# ------------------------------------------------------------------------------

output "org_root_id" {
  description = "Root ID of the organization"
  value       = aws_organizations_organization.org.roots[0].id
}

output "security_ou_id" {
  description = "OU ID for the Security OU"
  value       = aws_organizations_organizational_unit.security.id
}

output "workloads_ou_id" {
  description = "OU ID for the Workloads OU"
  value       = aws_organizations_organizational_unit.workloads.id
}

output "workloads_prod_ou_id" {
  description = "OU ID for Production under Workloads"
  value       = aws_organizations_organizational_unit.workloads_prod.id
}

output "workloads_dev_ou_id" {
  description = "OU ID for Development under Workloads"
  value       = aws_organizations_organizational_unit.workloads_dev.id
}

output "sandbox_ou_id" {
  description = "OU ID for the Sandbox OU"
  value       = aws_organizations_organizational_unit.sandbox.id
}
