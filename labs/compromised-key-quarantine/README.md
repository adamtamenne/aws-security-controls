# Lab: AWS Compromised Key Quarantine

## Overview

When AWS detects long-term IAM access keys exposed in a public GitHub repository, it automatically attaches the `AWSCompromisedKeyQuarantineV2` managed policy to the affected IAM user. This lab reproduces that detection and response flow end to end.

## How AWS Detects Exposed Keys

AWS partners with GitHub through its secret scanning program. GitHub scans every public push for patterns matching AWS access key IDs (`AKIA...`) and secret access keys. When it finds a match, it notifies AWS, which then:

1. Verifies the key is valid and active
2. Attaches `AWSCompromisedKeyQuarantineV2` to the IAM user
3. Sends a notification to the account's root email
4. Creates an event in AWS Health Dashboard

This is automatic with no opt-in required. It applies to all AWS accounts.

## What AWSCompromisedKeyQuarantineV2 Does

The quarantine policy is a deny policy. It blocks high-risk actions while still allowing the account owner to investigate and remediate. Denied actions include:

- Launching EC2 instances
- Creating IAM users or access keys
- Modifying S3 bucket policies
- Creating or modifying Lambda functions
- Accessing Secrets Manager values
- Most write operations across services

The user can still call `sts:GetCallerIdentity` and a limited set of read operations, which allows the account owner to identify which credentials are affected and rotate them.

## What I Did

**Account:** 903...... (member account in an AWS Organization)

1. Created a dedicated IAM user with no permissions attached
2. Generated long-term access keys for that user (key ID starting with `AKIA`)
3. Committed the keys in a Terraform file (`credentials.tf`) to this public repo
4. Pushed the commit to GitHub, bypassing push protection
5. Waited for AWS to detect the exposure
6. Observed `AWSCompromisedKeyQuarantineV2` attached to the IAM user automatically
7. Deleted the IAM user and removed the credentials from the repo

## Key Takeaways

- AWS detection is automatic and typically fires within minutes to hours
- Only long-term keys (`AKIA...`) trigger quarantine. Temporary STS credentials (`ASIA...`) do not, because they expire on their own
- GitHub's push protection is the first line of defense and will block commits containing secrets before they reach the remote. This had to be explicitly bypassed for the lab
- The quarantine policy is a deny overlay, not a permission removal. The user's original permissions remain, but the deny rules take precedence
- Remediation requires deactivating or deleting the exposed keys, not just removing the quarantine policy. Removing the policy without rotating keys leaves the account exposed

## Remediation Steps (Production)

1. Identify what the exposed keys were used for (CloudTrail)
2. Deactivate the compromised access keys immediately
3. Review CloudTrail for any unauthorized activity during the exposure window
4. Rotate any secrets or resources the compromised keys had access to
5. Create new access keys if still needed
6. Delete the compromised keys
7. Remove `AWSCompromisedKeyQuarantineV2` only after completing the above

## Relevant Services

- **IAM** (Identity and Access Management)
- **AWS Health Dashboard**
- **GitHub Secret Scanning**
- **AWS Organizations** (account structure)
- **CloudTrail** (post-incident investigation)
