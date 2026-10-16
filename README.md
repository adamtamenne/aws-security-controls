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
| [Compromised Key Quarantine](labs/compromised-key-quarantine/) | 1. Threat Detection & Incident Response | Triggering AWS's automatic credential quarantine by exposing IAM keys in a public repo | [Vulnerable Infrastructure](labs/vulnerable-infra/) | 3. Infrastructure Security | Intentionally misconfigured Terraform (public RDS, open security groups, unencrypted storage, hardcoded secrets, IMDSv1) scanned with Checkov. 22 passed, 35 failed. |


## IaC Security Scanning

The `labs/vulnerable-infra/` directory contains intentionally misconfigured Terraform to demonstrate infrastructure-as-code scanning with Checkov. This is the same concept as SAST for application code, but applied to infrastructure definitions.

Checkov scans Terraform files against hundreds of security rules and catches misconfigurations before they're deployed. Running Checkov against the vulnerable infrastructure file produces 35 failures across:

| Resource | Key Findings |
|----------|-------------|
| S3 Bucket | No encryption, no access logging, no versioning, no public access block |
| Security Groups | SSH open to 0.0.0.0/0, all ports open, unrestricted egress, orphaned groups |
| RDS Database | Publicly accessible, unencrypted, hardcoded password, no audit logging |
| KMS Key | Key rotation disabled |
| Launch Configuration | Unencrypted EBS, IMDSv1 enabled (SSRF risk) |
| Lambda Function | Secrets in environment variables, no VPC, no code signing |

```bash
# Scan with Checkov
checkov -d labs/vulnerable-infra --framework terraform
```

In a pipeline, you'd add Checkov the same way you add Semgrep: scan on every PR, block on critical findings, and tune from there.