# Cloud Security Posture Scanner

A CSPM-lite scanner that audits an exported cloud configuration (JSON) for common
misconfigurations across AWS- and Azure-style resources in a single file. It is a
portfolio/teaching tool in the spirit of commercial CSPM products (Wiz, Prisma Cloud,
Microsoft Defender for Cloud), reduced to one dependency-free Python file.

## Why this exists

The most damaging cloud incidents rarely involve zero-days — they involve a security
group open to `0.0.0.0/0` on SSH, a public storage bucket, an unencrypted disk, or an
admin policy with `*` on `*`. This scanner codifies those checks so a configuration
export can be reviewed in seconds, with evidence and a remediation for every finding.

## Checks implemented (13)

| # | Check | Severity |
|---|-------|----------|
| 1 | Security group / NSG rule open to `0.0.0.0/0` on SSH (22) or RDP (3389) | High |
| 2 | Security group / NSG rule open to `0.0.0.0/0` on a database port (3306, 5432, 6379) | Critical |
| 3 | Publicly accessible storage bucket / blob container | High |
| 4 | Unencrypted storage, bucket, or disk | High |
| 5 | Storage without access logging | Medium |
| 6 | Root/admin account without MFA | Critical |
| 7 | Overly permissive IAM policy (`Action: "*"` on `Resource: "*"`) | Critical |
| 8 | Instance with a public IP in a private-tagged subnet | High |
| 9 | VPC flow logs disabled | Medium |
| 10 | Azure Network Watcher disabled | Medium |
| 11 | Database publicly accessible (RDS / Azure SQL) | Critical |
| 12 | Snapshot shared publicly | High |
| 13 | (grouped with #1/#2) IPv6 `::/0` and `*` sources treated as world-open | — |

## Input format

A single JSON object with a `resources` list. Each resource has a `type`, a `name`,
and a flat `properties` object using the documented property names:

```json
{
  "resources": [
    {"type": "aws_security_group", "name": "web-sg",
     "properties": {"rules": [{"cidr": "0.0.0.0/0", "port": 22}]}},
    {"type": "aws_s3_bucket", "name": "assets",
     "properties": {"public_access": false, "encryption_enabled": true,
                    "access_logging_enabled": true}},
    {"type": "azure_virtual_network", "name": "prod-vnet",
     "properties": {"network_watcher_enabled": true}}
  ]
}
```

Supported types include `aws_security_group`, `azure_nsg`, `aws_s3_bucket`,
`azure_storage_account`, `azure_blob_container`, `aws_ebs_volume`,
`azure_managed_disk`, `aws_iam_user`, `aws_iam_policy`, `aws_instance`,
`azure_virtual_machine`, `aws_vpc`, `azure_virtual_network`, `aws_rds_instance`,
`azure_sql_database`, `aws_ebs_snapshot`, and `azure_snapshot`. The bundled
`sample-data/cloud-export.json` is a complete worked example of the format.

## Run it

Demo (bundled fictional export, fully offline):

```bash
python3 scanner.py --demo
```

Against your own export:

```bash
python3 scanner.py --file export.json
```

Python 3, standard library only. Findings are printed grouped by severity, each with
the resource, the check, the evidence taken from the export, and a remediation. The
report ends with a **posture score**: 100 minus penalties (Critical ×5, High ×3,
Medium ×1), floored at 0.

## Demo output (actual run)

```text
Cloud Security Posture Scan
Source: demo sample data (cloud-export.json)
Resources scanned: 19

== Critical (4) ==
  [Network rule open to the world on a sensitive port]
    Resource:    azure_nsg / app-nsg
    Evidence:    Rule allows 0.0.0.0/0 to port 5432 (PostgreSQL).
    Remediation: Restrict the source range to a bastion/VPN CIDR or remove the rule.
  [Root/admin account without MFA]
    Resource:    aws_iam_user / root
    Evidence:    Privileged account has mfa_enabled = false.
    Remediation: Enable MFA on the root/admin account and use it only for break-glass tasks.
  [Overly permissive IAM policy (wildcard action and resource)]
    Resource:    aws_iam_policy / legacy-admin-policy
    Evidence:    Policy allows Action "*" on Resource "*".
    Remediation: Scope the policy to the specific actions and resource ARNs the workload needs.
  [Database is publicly accessible]
    Resource:    aws_rds_instance / orders-db
    Evidence:    Public accessibility is enabled on the database endpoint.
    Remediation: Place the database in private subnets and reach it through the application tier only.

== High (9) ==
  [Network rule open to the world on a sensitive port]
    Resource:    aws_security_group / legacy-admin-sg
    Evidence:    Rule allows 0.0.0.0/0 to port 22 (SSH).
    Remediation: Restrict the source range to a bastion/VPN CIDR or remove the rule.
  [Network rule open to the world on a sensitive port]
    Resource:    aws_security_group / legacy-admin-sg
    Evidence:    Rule allows 0.0.0.0/0 to port 3389 (RDP).
    Remediation: Restrict the source range to a bastion/VPN CIDR or remove the rule.
  [Storage is publicly accessible]
    Resource:    aws_s3_bucket / public-assets
    Evidence:    Public access setting: True.
    Remediation: Disable public access and serve content through signed URLs or a CDN.
  [Storage or disk is unencrypted]
    Resource:    aws_s3_bucket / analytics-data
    Evidence:    Encryption at rest is disabled.
    Remediation: Enable server-side encryption (SSE/KMS or platform-managed keys).
  [Storage is publicly accessible]
    Resource:    azure_blob_container / customer-uploads-blob
    Evidence:    Public access setting: blob.
    Remediation: Disable public access and serve content through signed URLs or a CDN.
  [Storage or disk is unencrypted]
    Resource:    azure_managed_disk / payments-db-disk
    Evidence:    Encryption at rest is disabled.
    Remediation: Enable server-side encryption (SSE/KMS or platform-managed keys).
  [Instance with a public IP in a private-tagged subnet]
    Resource:    aws_instance / app-server-1
    Evidence:    public_ip = true while subnet_tag = 'private'.
    Remediation: Remove the public IP; reach the instance via bastion, VPN, or a load balancer.
  [Snapshot is shared publicly]
    Resource:    aws_ebs_snapshot / nightly-snapshot-2026-01
    Evidence:    Snapshot share settings grant public access.
    Remediation: Remove the public share; share only with named accounts/subscriptions when required.
  [Storage or disk is unencrypted]
    Resource:    azure_storage_account / archivefiles
    Evidence:    Encryption at rest is disabled.
    Remediation: Enable server-side encryption (SSE/KMS or platform-managed keys).

== Medium (3) ==
  [Storage access logging is disabled]
    Resource:    aws_s3_bucket / analytics-data
    Evidence:    No access logging configured for this storage resource.
    Remediation: Enable access/server-access logging to a separate audit account or workspace.
  [VPC flow logs are disabled]
    Resource:    aws_vpc / main-vpc
    Evidence:    flow_logs_enabled = false.
    Remediation: Enable VPC flow logs and ship them to a central log archive.
  [Storage access logging is disabled]
    Resource:    azure_storage_account / archivefiles
    Evidence:    No access logging configured for this storage resource.
    Remediation: Enable access/server-access logging to a separate audit account or workspace.

== Low (0) ==

Total findings: 16 (Critical: 4, High: 9, Medium: 3, Low: 0)
Posture score: 50/100 (100 minus penalties: Critical x5, High x3, Medium x1)
```

The sample export contains 19 fictional resources — a deliberate mix of compliant
resources (which produce no findings) and misconfigured ones.

## Design notes and limitations

- **Offline and read-only.** The scanner never calls a cloud API; it audits an export
  you provide. That makes it safe to run anywhere, but the export format is a
  simplified model, not the raw AWS/Azure API shape — a small normalisation step
  would be needed to feed it real account data.
- **A missing property is not a finding.** Checks fire on explicit values
  (`encryption_enabled: false`), not on absent fields, to avoid false positives from
  partial exports. The trade-off is that an incomplete export can hide issues.
- **Coarse IAM analysis.** The policy check detects the full wildcard case
  (`"*"` on `"*"`) only; it does not evaluate partial wildcards, conditions, or
  effective permissions. For deep IAM analysis see the companion
  `cloud-iam-policy-analyzer` project.
- **The posture score is a triage aid**, not a compliance verdict: it weights finding
  severity only, not asset criticality or exposure duration.
- Sample data is entirely fictional. No real account data is included or required.

## License

MIT — see `LICENSE`.
