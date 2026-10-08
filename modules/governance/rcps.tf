# ------------------------------------------------------------------------------
# Resource Control Policies (RCPs)
# ------------------------------------------------------------------------------
# RCPs are the complement to SCPs. Where SCPs limit what PRINCIPALS can do,
# RCPs limit what can be done TO RESOURCES regardless of who is doing it.
#
# Key difference:
#   SCP  = "No one in this account can call s3:PutObject without encryption"
#   RCP  = "This S3 bucket cannot accept unencrypted objects, even from
#           cross-account roles or AWS service principals"
#
# RCPs protect resources from external access patterns that SCPs can't reach
# because SCPs only apply to principals within the org. An external role
# accessing a resource-policy-shared bucket bypasses SCPs entirely, but
# an RCP on that resource still applies.
#
# RCPs support a subset of services (S3, STS, KMS, SQS, Secrets Manager
# as of 2024). Check the AWS docs for the current list.
# ------------------------------------------------------------------------------


# ------------------------------------------------------------------------------
# RCP 1: Deny Unencrypted S3 Uploads
# ------------------------------------------------------------------------------
# Forces server-side encryption on every S3 PutObject, regardless of who
# is uploading. Even a cross-account role with an s3:PutObject resource
# policy can't upload unencrypted objects.
#
# This is stronger than the equivalent SCP because it covers access from
# outside the organization (service principals, cross-account sharing).

resource "aws_organizations_policy" "rcp_deny_unencrypted_s3" {
  name        = "rcp-deny-unencrypted-s3-uploads"
  description = "Deny S3 PutObject without server-side encryption on all resources in the org"
  type        = "RESOURCE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyUnencryptedUploads"
        Effect    = "Deny"
        Action    = "s3:PutObject"
        Resource  = "*"
        Condition = {
          StringNotEquals = {
            "s3:x-amz-server-side-encryption" = [
              "aws:kms",
              "AES256",
            ]
          }
          Null = {
            "s3:x-amz-server-side-encryption" = "false"
          }
        }
      },
      {
        # Also deny if the header is completely missing
        Sid       = "DenyMissingEncryptionHeader"
        Effect    = "Deny"
        Action    = "s3:PutObject"
        Resource  = "*"
        Condition = {
          Null = {
            "s3:x-amz-server-side-encryption" = "true"
          }
        }
      }
    ]
  })
}

resource "aws_organizations_policy_attachment" "rcp_deny_unencrypted_s3_to_workloads" {
  policy_id = aws_organizations_policy.rcp_deny_unencrypted_s3.id
  target_id = aws_organizations_organizational_unit.workloads.id
}


# ------------------------------------------------------------------------------
# RCP 2: Restrict S3 Access to Organization Only
# ------------------------------------------------------------------------------
# Denies any S3 action on resources in this OU unless the caller is from
# within the organization. This prevents data exfiltration via resource
# policies that grant access to external accounts.
#
# aws:PrincipalOrgID checks whether the calling principal belongs to this
# org. Requests from outside the org are denied at the resource level.

resource "aws_organizations_policy" "rcp_s3_org_only" {
  name        = "rcp-restrict-s3-to-org"
  description = "Deny S3 access from principals outside the organization"
  type        = "RESOURCE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyExternalS3Access"
        Effect    = "Deny"
        Action    = "s3:*"
        Resource  = "*"
        Condition = {
          StringNotEquals = {
            "aws:PrincipalOrgID" = aws_organizations_organization.org.id
          }
          # Don't block AWS service principals (CloudTrail writing logs, etc.)
          Bool = {
            "aws:PrincipalIsAWSService" = "false"
          }
        }
      }
    ]
  })
}

resource "aws_organizations_policy_attachment" "rcp_s3_org_only_to_workloads" {
  policy_id = aws_organizations_policy.rcp_s3_org_only.id
  target_id = aws_organizations_organizational_unit.workloads.id
}


# ------------------------------------------------------------------------------
# RCP 3: Restrict STS AssumeRole to Organization
# ------------------------------------------------------------------------------
# Prevents roles in member accounts from being assumed by principals outside
# the org. Even if someone accidentally puts a wildcard in a role trust
# policy, this RCP blocks the cross-account assume from external accounts.

resource "aws_organizations_policy" "rcp_sts_org_only" {
  name        = "rcp-restrict-sts-to-org"
  description = "Deny STS AssumeRole from principals outside the organization"
  type        = "RESOURCE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyExternalAssumeRole"
        Effect    = "Deny"
        Action    = [
          "sts:AssumeRole",
          "sts:AssumeRoleWithSAML",
          "sts:AssumeRoleWithWebIdentity",
        ]
        Resource  = "*"
        Condition = {
          StringNotEquals = {
            "aws:PrincipalOrgID" = aws_organizations_organization.org.id
          }
          Bool = {
            "aws:PrincipalIsAWSService" = "false"
          }
        }
      }
    ]
  })
}

resource "aws_organizations_policy_attachment" "rcp_sts_org_only_to_workloads" {
  policy_id = aws_organizations_policy.rcp_sts_org_only.id
  target_id = aws_organizations_organizational_unit.workloads.id
}
