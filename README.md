# AWS Security Controls

Terraform modules implementing AWS security controls

Each module deploys real, production-grade security controls — not just documentation. The repo grows incrementally as I work through each exam domain.

## Exam Domain Mapping

| Domain | Weight | Module | Status |
|--------|--------|--------|--------|
| 1. Threat Detection & Incident Response | 14% | `modules/threat-detection/` | In Progress |
| 2. Security Logging & Monitoring | 18% | `modules/logging/` | Planned |
| 3. Infrastructure Security | 20% | `modules/infrastructure/` | Planned |
| 4. Identity & Access Management | 16% | `modules/iam/` | Planned |
| 5. Data Protection | 18% | `modules/data-protection/` | Planned |
| 6. Management & Security Governance | 14% | `modules/governance/` | In Progress |

## Current Modules

### Governance (`modules/governance/`)
- **Organizations** — Multi-account OU structure (Security, Workloads, Sandbox)
- **Service Control Policies (SCPs)** — Preventive guardrails: deny root access, restrict regions, require IMDSv2, block S3 public access
- **Resource Control Policies (RCPs)** — Resource-level guardrails: deny unencrypted S3 uploads, restrict cross-account access

## Usage

```bash
# Initialize Terraform
terraform init

# Preview what would be created
terraform plan

# Deploy (requires AWS credentials configured)
terraform apply

# Tear down
terraform destroy
```

## Prerequisites

- [Terraform](https://developer.hashicorp.com/terraform/install) >= 1.5
- AWS CLI configured with credentials (`aws configure`)
- An AWS Organization (management account)

## Labs

Hands-on exercises reproducing real AWS security scenarios.

| Lab | Domain | Description |
|-----|--------|-------------|
| [Compromised Key Quarantine](labs/compromised-key-quarantine/) | 1. Threat Detection & Incident Response | Triggering AWS's automatic credential quarantine by exposing IAM keys in a public repo |
