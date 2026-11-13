#!/usr/bin/env python3
"""CSPM-lite scanner: audit an exported cloud configuration for common misconfigurations.

Reads a single JSON export (AWS- and Azure-style resources in one file) and
reports findings grouped by severity, plus a simple posture score.
Standard library only; runs fully offline.

Usage:
    python3 scanner.py --demo
    python3 scanner.py --file export.json
"""

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]
SCORE_PENALTY = {"Critical": 5, "High": 3, "Medium": 1, "Low": 1}
SENSITIVE_PORTS = {22: "SSH", 3389: "RDP", 3306: "MySQL",
                   5432: "PostgreSQL", 6379: "Redis"}
DATABASE_PORTS = {3306, 5432, 6379}
STORAGE_TYPES = {"aws_s3_bucket", "azure_storage_account", "azure_blob_container",
                 "aws_ebs_volume", "azure_managed_disk"}


class Finding:
    def __init__(self, severity, check, resource, evidence, remediation):
        self.severity = severity
        self.check = check
        self.resource = resource
        self.evidence = evidence
        self.remediation = remediation


def load_export(path):
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict) or not isinstance(data.get("resources"), list):
        raise ValueError('export must be a JSON object with a "resources" list')
    return data["resources"]


def label(resource):
    return f"{resource.get('type', '?')} / {resource.get('name', '?')}"


def check_open_sensitive_ports(resource, props, findings):
    if resource.get("type") not in ("aws_security_group", "azure_nsg"):
        return
    for rule in props.get("rules", []):
        cidr = str(rule.get("cidr", rule.get("source", "")))
        if cidr not in ("0.0.0.0/0", "::/0", "*"):
            continue
        lo = int(rule.get("from_port", rule.get("port", 0)))
        hi = int(rule.get("to_port", rule.get("port", lo)))
        for port, service in SENSITIVE_PORTS.items():
            if lo <= port <= hi:
                severity = "Critical" if port in DATABASE_PORTS else "High"
                findings.append(Finding(
                    severity, "Network rule open to the world on a sensitive port",
                    label(resource),
                    f"Rule allows {cidr} to port {port} ({service}).",
                    "Restrict the source range to a bastion/VPN CIDR or remove the rule."))


def check_storage(resource, props, findings):
    rtype = resource.get("type")
    if rtype not in STORAGE_TYPES:
        return
    public = props.get("public_access")
    if public is True or (isinstance(public, str) and public.lower() in ("public", "blob", "container")) \
            or props.get("acl") in ("public-read", "public-read-write"):
        findings.append(Finding(
            "High", "Storage is publicly accessible", label(resource),
            f"Public access setting: {public or props.get('acl')}.",
            "Disable public access and serve content through signed URLs or a CDN."))
    encrypted = props.get("encryption_enabled", props.get("encrypted"))
    if encrypted is False:
        findings.append(Finding(
            "High", "Storage or disk is unencrypted", label(resource),
            "Encryption at rest is disabled.",
            "Enable server-side encryption (SSE/KMS or platform-managed keys)."))
    logging = props.get("access_logging_enabled", props.get("access_logging"))
    if logging is False:
        findings.append(Finding(
            "Medium", "Storage access logging is disabled", label(resource),
            "No access logging configured for this storage resource.",
            "Enable access/server-access logging to a separate audit account or workspace."))


def check_iam(resource, props, findings):
    rtype = resource.get("type")
    if rtype == "aws_iam_user" or rtype == "azure_ad_user":
        is_root = props.get("is_root_account") or props.get("name") in ("root", "admin")
        if is_root and props.get("mfa_enabled") is False:
            findings.append(Finding(
                "Critical", "Root/admin account without MFA", label(resource),
                "Privileged account has mfa_enabled = false.",
                "Enable MFA on the root/admin account and use it only for break-glass tasks."))
    if rtype in ("aws_iam_policy", "azure_role_assignment"):
        for stmt in props.get("policy_document", {}).get("Statement", []):
            actions = stmt.get("Action", [])
            actions = [actions] if isinstance(actions, str) else actions
            resources = stmt.get("Resource", [])
            resources = [resources] if isinstance(resources, str) else resources
            if stmt.get("Effect") == "Allow" and "*" in actions and "*" in resources:
                findings.append(Finding(
                    "Critical", "Overly permissive IAM policy (wildcard action and resource)",
                    label(resource),
                    'Policy allows Action "*" on Resource "*".',
                    "Scope the policy to the specific actions and resource ARNs the workload needs."))


def check_instance_subnet(resource, props, findings):
    if resource.get("type") not in ("aws_instance", "azure_virtual_machine"):
        return
    subnet_tag = str(props.get("subnet_tag", props.get("subnet_type", ""))).lower()
    if props.get("public_ip") and subnet_tag == "private":
        findings.append(Finding(
            "High", "Instance with a public IP in a private-tagged subnet", label(resource),
            "public_ip = true while subnet_tag = 'private'.",
            "Remove the public IP; reach the instance via bastion, VPN, or a load balancer."))


def check_network_telemetry(resource, props, findings):
    rtype = resource.get("type")
    if rtype == "aws_vpc" and props.get("flow_logs_enabled") is False:
        findings.append(Finding(
            "Medium", "VPC flow logs are disabled", label(resource),
            "flow_logs_enabled = false.",
            "Enable VPC flow logs and ship them to a central log archive."))
    if rtype == "azure_virtual_network" and props.get("network_watcher_enabled") is False:
        findings.append(Finding(
            "Medium", "Network Watcher is disabled for the virtual network", label(resource),
            "network_watcher_enabled = false.",
            "Enable Network Watcher and NSG flow logs for the region."))


def check_database(resource, props, findings):
    if resource.get("type") not in ("aws_rds_instance", "azure_sql_database"):
        return
    public = props.get("publicly_accessible")
    if public is None:
        public = str(props.get("public_network_access", "")).lower() == "enabled"
    if public:
        findings.append(Finding(
            "Critical", "Database is publicly accessible", label(resource),
            "Public accessibility is enabled on the database endpoint.",
            "Place the database in private subnets and reach it through the application tier only."))


def check_snapshot(resource, props, findings):
    if resource.get("type") not in ("aws_ebs_snapshot", "azure_snapshot"):
        return
    if props.get("shared_public") or str(props.get("share_permissions", "")).lower() == "public":
        findings.append(Finding(
            "High", "Snapshot is shared publicly", label(resource),
            "Snapshot share settings grant public access.",
            "Remove the public share; share only with named accounts/subscriptions when required."))


CHECKS = [check_open_sensitive_ports, check_storage, check_iam,
          check_instance_subnet, check_network_telemetry, check_database,
          check_snapshot]


def scan(resources):
    findings = []
    for resource in resources:
        props = resource.get("properties", {}) or {}
        for check in CHECKS:
            check(resource, props, findings)
    return findings


def posture_score(findings):
    penalty = sum(SCORE_PENALTY[f.severity] for f in findings)
    return max(0, 100 - penalty)


def print_report(resources, findings, source):
    print("Cloud Security Posture Scan")
    print(f"Source: {source}")
    print(f"Resources scanned: {len(resources)}")
    print()
    grouped = defaultdict(list)
    for finding in findings:
        grouped[finding.severity].append(finding)
    for severity in SEVERITY_ORDER:
        items = grouped.get(severity, [])
        print(f"== {severity} ({len(items)}) ==")
        for f in items:
            print(f"  [{f.check}]")
            print(f"    Resource:    {f.resource}")
            print(f"    Evidence:    {f.evidence}")
            print(f"    Remediation: {f.remediation}")
        print()
    counts = ", ".join(f"{sev}: {len(grouped.get(sev, []))}" for sev in SEVERITY_ORDER)
    print(f"Total findings: {len(findings)} ({counts})")
    print(f"Posture score: {posture_score(findings)}/100 "
          f"(100 minus penalties: Critical x5, High x3, Medium x1)")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--demo", action="store_true",
                       help="scan the bundled fictional sample export")
    group.add_argument("--file", metavar="EXPORT.json",
                       help="scan an exported cloud configuration JSON file")
    args = parser.parse_args(argv)

    if args.demo:
        path = Path(__file__).parent / "sample-data" / "cloud-export.json"
        source = f"demo sample data ({path.name})"
    else:
        path = Path(args.file)
        source = str(path)
    try:
        resources = load_export(path)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: could not load export: {exc}", file=sys.stderr)
        return 2
    print_report(resources, scan(resources), source)
    return 0


if __name__ == "__main__":
    sys.exit(main())
