# ------------------------------------------------------------------------------
# Service Control Policies (SCPs)
# ------------------------------------------------------------------------------
# SCPs set the MAXIMUM permissions for accounts in an OU. They don't grant
# access — they set the outer boundary. Even if an IAM policy says Allow,
# the SCP can deny it.
#
# Key concept: SCPs use the same policy language as IAM but they apply to
# every principal in the attached account EXCEPT the management account.
# The management account is immune to SCPs, which is why you should never
# run workloads in it.
#
# Evaluation: an action must be allowed by BOTH the SCP and the identity
# policy. If either denies, the action is denied.
# ------------------------------------------------------------------------------


# ------------------------------------------------------------------------------
# SCP 1: Deny Root User Access
# ------------------------------------------------------------------------------
# The root user in member accounts should never be used. This SCP blocks all
# actions by the root principal. The management account root is NOT affected
# (SCPs don't apply to the management account).

resource "aws_organizations_policy" "deny_root" {
  name        = "deny-root-user-access"
  description = "Prevent root user from performing any action in member accounts"
  type        = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyRootUser"
        Effect    = "Deny"
        Action    = "*"
        Resource  = "*"
        Condition = {
          StringLike = {
            "aws:PrincipalArn" = "arn:aws:iam::*:root"
          }
        }
      }
    ]
  })
}

resource "aws_organizations_policy_attachment" "deny_root_to_workloads" {
  policy_id = aws_organizations_policy.deny_root.id
  target_id = aws_organizations_organizational_unit.workloads.id
}

resource "aws_organizations_policy_attachment" "deny_root_to_sandbox" {
  policy_id = aws_organizations_policy.deny_root.id
  target_id = aws_organizations_organizational_unit.sandbox.id
}


# ------------------------------------------------------------------------------
# SCP 2: Restrict to Approved Regions
# ------------------------------------------------------------------------------
# Limits resource creation to specific regions. This prevents data residency
# issues and reduces the attack surface (fewer regions to monitor).
#
# NotAction is used instead of Action because some AWS services are global
# (IAM, Organizations, STS, Support) and would break if region-restricted.

resource "aws_organizations_policy" "restrict_regions" {
  name        = "restrict-to-approved-regions"
  description = "Deny resource creation outside approved AWS regions"
  type        = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyUnapprovedRegions"
        Effect    = "Deny"
        NotAction = [
          "iam:*",
          "organizations:*",
          "sts:*",
          "support:*",
          "budgets:*",
          "cloudfront:*",
          "route53:*",
          "wafv2:*",
          "shield:*",
        ]
        Resource = "*"
        Condition = {
          StringNotEquals = {
            "aws:RequestedRegion" = var.approved_regions
          }
        }
      }
    ]
  })
}

resource "aws_organizations_policy_attachment" "restrict_regions_to_workloads" {
  policy_id = aws_organizations_policy.restrict_regions.id
  target_id = aws_organizations_organizational_unit.workloads.id
}


# ------------------------------------------------------------------------------
# SCP 3: Require IMDSv2 on EC2 Instances
# ------------------------------------------------------------------------------
# Instance Metadata Service v1 (IMDSv1) is a common SSRF attack vector.
# An attacker who can reach 169.254.169.254 from inside the instance can
# steal the role credentials. IMDSv2 requires a PUT request with a hop-limit
# token, which blocks most SSRF exploits.
#
# This SCP denies RunInstances unless the metadata options require IMDSv2.

resource "aws_organizations_policy" "require_imdsv2" {
  name        = "require-imdsv2"
  description = "Deny EC2 instance launches that don't enforce IMDSv2"
  type        = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "RequireIMDSv2"
        Effect    = "Deny"
        Action    = "ec2:RunInstances"
        Resource  = "arn:aws:ec2:*:*:instance/*"
        Condition = {
          StringNotEquals = {
            "ec2:MetadataHttpTokens" = "required"
          }
        }
      }
    ]
  })
}

resource "aws_organizations_policy_attachment" "require_imdsv2_to_workloads" {
  policy_id = aws_organizations_policy.require_imdsv2.id
  target_id = aws_organizations_organizational_unit.workloads.id
}


# ------------------------------------------------------------------------------
# SCP 4: Block S3 Public Access Changes
# ------------------------------------------------------------------------------
# Prevents anyone from disabling S3 Block Public Access at the account level.
# Even if a developer has full S3 permissions via IAM, this SCP stops them
# from making buckets publicly accessible.

resource "aws_organizations_policy" "deny_s3_public" {
  name        = "deny-s3-public-access-changes"
  description = "Prevent disabling S3 Block Public Access settings"
  type        = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyS3PublicAccessChanges"
        Effect = "Deny"
        Action = [
          "s3:PutBucketPublicAccessBlock",
          "s3:PutAccountPublicAccessBlock",
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_organizations_policy_attachment" "deny_s3_public_to_workloads" {
  policy_id = aws_organizations_policy.deny_s3_public.id
  target_id = aws_organizations_organizational_unit.workloads.id
}


# ------------------------------------------------------------------------------
# SCP 5: Protect Security Services
# ------------------------------------------------------------------------------
# Prevents member accounts from disabling GuardDuty, Security Hub, CloudTrail,
# Config, or Access Analyzer. Even an admin in a member account can't turn
# off centralized security monitoring.

resource "aws_organizations_policy" "protect_security_services" {
  name        = "protect-security-services"
  description = "Prevent disabling centralized security services in member accounts"
  type        = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ProtectSecurityServices"
        Effect = "Deny"
        Action = [
          "guardduty:DeleteDetector",
          "guardduty:DisassociateFromMasterAccount",
          "guardduty:UpdateDetector",
          "securityhub:DisableSecurityHub",
          "securityhub:DeleteMembers",
          "securityhub:DisassociateFromMasterAccount",
          "cloudtrail:StopLogging",
          "cloudtrail:DeleteTrail",
          "config:StopConfigurationRecorder",
          "config:DeleteConfigurationRecorder",
          "access-analyzer:DeleteAnalyzer",
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_organizations_policy_attachment" "protect_security_to_all" {
  policy_id = aws_organizations_policy.protect_security_services.id
  target_id = aws_organizations_organization.org.roots[0].id
}
