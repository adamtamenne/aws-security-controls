output "organization_id" {
  description = "The ID of the AWS Organization"
  value       = aws_organizations_organization.org.id
}

output "organization_root_id" {
  description = "The root ID of the AWS Organization"
  value       = aws_organizations_organization.org.roots[0].id
}

output "ou_ids" {
  description = "Map of OU names to their IDs"
  value = {
    security        = aws_organizations_organizational_unit.security.id
    workloads       = aws_organizations_organizational_unit.workloads.id
    workloads_prod  = aws_organizations_organizational_unit.workloads_prod.id
    workloads_dev   = aws_organizations_organizational_unit.workloads_dev.id
    sandbox         = aws_organizations_organizational_unit.sandbox.id
  }
}

output "scp_ids" {
  description = "Map of SCP names to their IDs"
  value = {
    deny_root                = aws_organizations_policy.deny_root.id
    restrict_regions         = aws_organizations_policy.restrict_regions.id
    require_imdsv2           = aws_organizations_policy.require_imdsv2.id
    deny_s3_public           = aws_organizations_policy.deny_s3_public.id
    protect_security_services = aws_organizations_policy.protect_security_services.id
  }
}

output "rcp_ids" {
  description = "Map of RCP names to their IDs"
  value = {
    deny_unencrypted_s3 = aws_organizations_policy.rcp_deny_unencrypted_s3.id
    s3_org_only         = aws_organizations_policy.rcp_s3_org_only.id
    sts_org_only        = aws_organizations_policy.rcp_sts_org_only.id
  }
}
