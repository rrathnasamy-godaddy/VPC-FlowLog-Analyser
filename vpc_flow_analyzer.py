#!/usr/bin/env python3
"""
vpc_flow_analyzer.py  —  Self-contained VPC Flow Log analyzer (Parquet / S3)

No LLM required. Pure Python + boto3 + pyarrow.

Outputs — written to Report/<YYYY-MM-DD_HH-MM-SS>/ per scan run:
  <prefix>_detailed.txt       — every src→dst:port flow with accept/reject counts
  <prefix>_summary.txt        — per-IP totals + IPs flagged for review
  <prefix>_mapping.txt        — one row per (src, dst) pair: accepted/rejected totals
  <prefix>_securityReview.txt — IPs with high egress volume or high egress failure rate

Usage:
  python3 vpc_flow_analyzer.py --region us-east-1 --date 2026-09-23
  python3 vpc_flow_analyzer.py --region us-east-1 --date 2026-09-23 --hours 9-12
  python3 vpc_flow_analyzer.py --region us-east-1 --date 2026-09-23 --hours 0,6,12,18
  python3 vpc_flow_analyzer.py --region us-east-1 --date 2026-09-23 --hours 9-12 --no-discovery

Requirements:
  pip3 install boto3 pyarrow

Credentials (any of the standard AWS mechanisms):
  AWS_PROFILE / AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY [+ AWS_SESSION_TOKEN]
  AWS_DEFAULT_REGION is overridden by --region
"""

import argparse
import csv
import datetime
import ipaddress
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
from collections import defaultdict
from pathlib import Path

try:
    import boto3
except ImportError:
    sys.exit("ERROR: boto3 required.  Run: pip3 install boto3")

try:
    import pyarrow.parquet as pq
except ImportError:
    sys.exit("ERROR: pyarrow required.  Run: pip3 install pyarrow")


# ── Constants ──────────────────────────────────────────────────────────────────

ADMIN_PORTS = {
    22: "SSH", 23: "Telnet", 3389: "RDP",
    5985: "WinRM-HTTP", 5986: "WinRM-HTTPS",
    445: "SMB", 135: "MSRPC", 139: "NetBIOS",
    2049: "NFS", 5432: "PostgreSQL", 3306: "MySQL",
    1433: "MSSQL", 27017: "MongoDB", 6379: "Redis",
    9200: "Elasticsearch", 2181: "ZooKeeper",
    8500: "Consul", 4505: "SaltStack", 4506: "SaltStack",
    9090: "Prometheus", 9100: "NodeExporter",
}

PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
]

PROTOCOL_MAP = {6: "TCP", 17: "UDP", 1: "ICMP"}


def is_private(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in net for net in PRIVATE_NETS)
    except ValueError:
        return False


def fmt_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


# ── AWS: identity + flow log discovery ────────────────────────────────────────

def get_account_id() -> str:
    return boto3.client("sts").get_caller_identity()["Account"]


def discover_flow_log_s3(region: str) -> tuple[str, str]:
    """
    Return (bucket, base_key_prefix) for the first active S3 flow log in region.
    LogDestination is stored as an ARN: arn:aws:s3:::bucket/optional/prefix
    """
    ec2 = boto3.client("ec2", region_name=region)
    for fl in ec2.describe_flow_logs().get("FlowLogs", []):
        if fl.get("LogDestinationType") == "s3" and fl.get("FlowLogStatus") == "ACTIVE":
            dest = fl["LogDestination"].replace("arn:aws:s3:::", "")
            if "/" in dest:
                bucket, prefix = dest.split("/", 1)
                return bucket, prefix.rstrip("/")
            return dest, ""
    sys.exit(
        f"ERROR: No active S3 VPC flow logs found in region {region}.\n"
        "Verify with: aws ec2 describe-flow-logs --query 'FlowLogs[*].{{ID:FlowLogId,Dest:LogDestination,Status:FlowLogStatus}}'"
    )


def build_s3_prefixes(bucket: str, base_prefix: str, account_id: str,
                      region: str, date_str: str, hours: list[int]) -> list[str]:
    """
    Construct per-hour S3 URIs using the Hive-style partition layout AWS uses:
      <base>/AWSLogs/aws-account-id=NNN/aws-service=vpcflowlogs/aws-region=RRR/
             year=YYYY/month=MM/day=DD/hour=HH/
    """
    year, month, day = date_str.split("-")
    base = "/".join(filter(None, [base_prefix,
        f"AWSLogs/aws-account-id={account_id}/aws-service=vpcflowlogs",
        f"aws-region={region}/year={year}/month={month}/day={day}",
    ]))
    return [f"s3://{bucket}/{base}/hour={h:02d}/" for h in hours]


# ── AWS: service discovery ─────────────────────────────────────────────────────

def discover_services(region: str) -> dict:
    """
    Read-only pass over EC2 / ECS / RDS to build ip → {name, type, id}.
    Errors are non-fatal — a partial map is better than none.
    """
    ip_map: dict = {}
    sess = boto3.Session(region_name=region)

    # EC2
    try:
        ec2 = sess.client("ec2")
        for page in ec2.get_paginator("describe_instances").paginate():
            for res in page["Reservations"]:
                for inst in res["Instances"]:
                    iid = inst["InstanceId"]
                    name = next((t["Value"] for t in inst.get("Tags", []) if t["Key"] == "Name"), iid)
                    for nic in inst.get("NetworkInterfaces", []):
                        for priv in nic.get("PrivateIpAddresses", []):
                            ip = priv.get("PrivateIpAddress", "")
                            if ip:
                                ip_map[ip] = {"name": name, "type": "EC2", "id": iid}
                        pub = nic.get("Association", {}).get("PublicIp", "")
                        if pub:
                            ip_map[pub] = {"name": name, "type": "EC2", "id": iid}
        _log(f"[discovery] EC2: {sum(1 for v in ip_map.values() if v['type']=='EC2')} IPs mapped.")
    except Exception as e:
        _log(f"[discovery] EC2 error: {e}")

    # ECS
    try:
        ecs = sess.client("ecs")
        for cluster_arn in ecs.list_clusters().get("clusterArns", []):
            task_arns: list = []
            for pg in ecs.get_paginator("list_tasks").paginate(cluster=cluster_arn):
                task_arns.extend(pg["taskArns"])
            for i in range(0, len(task_arns), 100):
                for task in ecs.describe_tasks(cluster=cluster_arn, tasks=task_arns[i:i+100]).get("tasks", []):
                    tdef = task.get("taskDefinitionArn", "").split("/")[-1]
                    for att in task.get("attachments", []):
                        for d in att.get("details", []):
                            if d["name"] == "privateIPv4Address":
                                ip_map[d["value"]] = {
                                    "name": tdef,
                                    "type": "ECS",
                                    "id": task["taskArn"].split("/")[-1],
                                }
        _log(f"[discovery] ECS: {sum(1 for v in ip_map.values() if v['type']=='ECS')} IPs mapped.")
    except Exception as e:
        _log(f"[discovery] ECS error: {e}")

    # RDS
    try:
        rds = sess.client("rds")
        for page in rds.get_paginator("describe_db_instances").paginate():
            for db in page["DBInstances"]:
                host = db.get("Endpoint", {}).get("Address", "")
                if host:
                    try:
                        ip = socket.gethostbyname(host)
                        ip_map[ip] = {"name": db["DBInstanceIdentifier"], "type": "RDS", "id": db["DBInstanceIdentifier"]}
                    except Exception:
                        pass
        _log(f"[discovery] RDS: {sum(1 for v in ip_map.values() if v['type']=='RDS')} IPs mapped.")
    except Exception as e:
        _log(f"[discovery] RDS error: {e}")

    _log(f"[discovery] Total: {len(ip_map)} IPs with service labels.")
    return ip_map


def svc_label(ip: str, ip_map: dict) -> str:
    info = ip_map.get(ip)
    if info:
        return f"{info['name']} [{info['type']}]"
    return ip


# ── S3 file streaming ─────────────────────────────────────────────────────────

def list_parquet_keys(s3_prefix: str) -> list[tuple[str, str]]:
    """Return [(bucket, key), ...] for all .parquet objects under s3_prefix."""
    without_scheme = s3_prefix.replace("s3://", "")
    bucket, key_prefix = without_scheme.split("/", 1)
    s3 = boto3.client("s3")
    keys = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=key_prefix):
        for obj in page.get("Contents", []):
            if obj["Key"].endswith(".parquet"):
                keys.append((bucket, obj["Key"]))
    return keys


def _s3_cp(bucket: str, key: str, dest: str) -> None:
    subprocess.run(
        ["aws", "s3", "cp", "--quiet", f"s3://{bucket}/{key}", dest],
        check=True, capture_output=True,
    )


def stream_parquet_records(s3_prefixes: list[str], tmp_dir: str):
    """
    For each Parquet file: download → yield records → delete local file.
    Max disk usage at any moment = size of the largest single file.
    """
    all_keys: list[tuple[str, str]] = []
    for prefix in s3_prefixes:
        all_keys.extend(list_parquet_keys(prefix))

    total = len(all_keys)
    _log(f"Found {total} Parquet files to process.")

    for idx, (bucket, key) in enumerate(all_keys, 1):
        fname = Path(key).name
        local = os.path.join(tmp_dir, fname)
        print(f"  [{idx:>5}/{total}] {fname}", file=sys.stderr, end="\r")
        try:
            _s3_cp(bucket, key, local)
            yield from _read_parquet(local)
        except Exception as e:
            print(f"\n  [skip] {fname}: {e}", file=sys.stderr)
        finally:
            if os.path.exists(local):
                os.unlink(local)

    print(f"\nStreamed all {total} files.", file=sys.stderr)


def _read_parquet(path: str):
    table = pq.read_table(path, columns=[
        "srcaddr", "dstaddr", "srcport", "dstport",
        "protocol", "bytes", "action",
    ])
    for batch in table.to_batches(max_chunksize=50_000):
        d = batch.to_pydict()
        n = batch.num_rows
        for i in range(n):
            action = d["action"][i]
            if action not in ("ACCEPT", "REJECT"):
                continue
            yield {
                "src":    d["srcaddr"][i] or "-",
                "dst":    d["dstaddr"][i] or "-",
                "dport":  int(d["dstport"][i] or 0),
                "proto":  int(d["protocol"][i] or 0),
                "bytes":  int(d["bytes"][i] or 0),
                "action": action,
            }


# ── Aggregation ────────────────────────────────────────────────────────────────

def aggregate(records):
    """
    pair_stats : {(src, dst, dport, proto) → {accept, reject, accept_bytes, reject_bytes}}
    ip_stats   : {ip → {in_accept, in_reject, in_bytes,
                         out_accept, out_reject, out_bytes,
                         admin_fans:  {port → set(dst_ips)},   # ACCEPT fan-out
                         reject_fans: {port → set(dst_ips)},   # REJECT fan-out on admin ports
                         reject_dests: set(all rejected dst_ips)}}
    """
    pair_stats: dict = defaultdict(lambda: {"accept": 0, "reject": 0, "accept_bytes": 0, "reject_bytes": 0})
    ip_stats:   dict = defaultdict(lambda: {
        "in_accept": 0, "in_reject": 0, "in_bytes": 0,
        "out_accept": 0, "out_reject": 0, "out_bytes": 0,
        "admin_fans": defaultdict(set),
        "reject_fans": defaultdict(set),
        "reject_dests": set(),
    })

    total = 0
    for rec in records:
        total += 1
        src, dst   = rec["src"], rec["dst"]
        dport, proto = rec["dport"], rec["proto"]
        action, nb = rec["action"], rec["bytes"]

        pk = (src, dst, dport, proto)
        if action == "ACCEPT":
            pair_stats[pk]["accept"]       += 1
            pair_stats[pk]["accept_bytes"] += nb
            ip_stats[src]["out_accept"]    += 1
            ip_stats[src]["out_bytes"]     += nb
            ip_stats[dst]["in_accept"]     += 1
            ip_stats[dst]["in_bytes"]      += nb
        else:
            pair_stats[pk]["reject"]       += 1
            pair_stats[pk]["reject_bytes"] += nb
            ip_stats[src]["out_reject"]    += 1
            ip_stats[dst]["in_reject"]     += 1

        # Lateral movement detection (egress from src)
        if is_private(src):
            if action == "ACCEPT" and is_private(dst) and dport in ADMIN_PORTS:
                ip_stats[src]["admin_fans"][dport].add(dst)
            if action == "REJECT":
                ip_stats[src]["reject_dests"].add(dst)
                if is_private(dst) and dport in ADMIN_PORTS:
                    ip_stats[src]["reject_fans"][dport].add(dst)

    _log(f"Processed {total:,} flow records across {len(ip_stats):,} unique IPs.")
    return pair_stats, ip_stats


# ── Flag logic ─────────────────────────────────────────────────────────────────

def get_flags(stat: dict, lat_thresh: int, rej_thresh: int) -> list[tuple[str, str]]:
    flags = []
    for port, dsts in stat["admin_fans"].items():
        if len(dsts) >= lat_thresh:
            flags.append(("HIGH",
                f"ACCEPT fan-out port {port}({ADMIN_PORTS.get(port,port)}) → {len(dsts)} distinct internal IPs"))
    for port, dsts in stat["reject_fans"].items():
        if len(dsts) >= lat_thresh:
            flags.append(("MEDIUM",
                f"REJECT fan-out port {port}({ADMIN_PORTS.get(port,port)}) → {len(dsts)} distinct internal IPs"))
    rd = len(stat["reject_dests"])
    tr = stat["out_reject"]
    if tr >= rej_thresh and rd >= lat_thresh * 2:
        sev = "HIGH" if rd > 20 else "MEDIUM"
        flags.append((sev, f"Reject storm: {tr:,} rejected egress → {rd} distinct destinations"))
    return flags


# ── Detailed report ────────────────────────────────────────────────────────────

def write_detailed(pair_stats: dict, ip_stats: dict, ip_map: dict,
                   out_path: str, lat_thresh: int, rej_thresh: int, top: int) -> None:
    """
    One section per source IP.
    Within each section: every destination IP with port, protocol, accept/reject counts and bytes.
    Flagged IPs appear first.
    """
    # Group by source
    by_src: dict = defaultdict(list)
    for (src, dst, dport, proto), counts in pair_stats.items():
        by_src[src].append((dst, dport, proto, counts))

    def src_sort(src):
        flags = get_flags(ip_stats[src], lat_thresh, rej_thresh)
        score = sum(2 if s == "HIGH" else 1 for s, _ in flags)
        vol   = sum(c["accept"] + c["reject"] for _, _, _, c in by_src[src])
        return (-score, -vol)

    with open(out_path, "w") as f:
        W = 110
        f.write("=" * W + "\n")
        f.write("VPC FLOW LOG — DETAILED IP-TO-IP CONNECTION REPORT\n")
        f.write(f"Source IPs: {len(by_src):,}    Unique (src,dst,port) pairs: {len(pair_stats):,}\n")
        f.write("=" * W + "\n\n")

        for src in sorted(by_src, key=src_sort):
            flows = by_src[src]
            flags = get_flags(ip_stats[src], lat_thresh, rej_thresh)
            flag_tag = "  *** FLAGGED FOR REVIEW ***" if flags else ""
            total_v  = sum(c["accept"] + c["reject"] for _, _, _, c in flows)

            f.write("-" * W + "\n")
            f.write(f"SOURCE: {src:<18}  {svc_label(src, ip_map)[:50]}{flag_tag}\n")
            if flags:
                for sev, msg in flags:
                    marker = "!!!" if sev == "HIGH" else " ! "
                    f.write(f"  [{marker}][{sev}]  {msg}\n")
            stat = ip_stats[src]
            f.write(f"  Egress  — accept: {stat['out_accept']:>8,}  reject: {stat['out_reject']:>8,}"
                    f"  bytes_sent: {fmt_bytes(stat['out_bytes'])}\n")
            f.write(f"  Ingress — accept: {stat['in_accept']:>8,}  reject: {stat['in_reject']:>8,}"
                    f"  bytes_recv: {fmt_bytes(stat['in_bytes'])}\n")
            f.write(f"  Unique destinations: {len(flows):,}    Total flows: {total_v:,}\n\n")

            # Column header
            f.write(f"  {'DESTINATION':<18} {'SERVICE / LABEL':<38} {'PORT':<12} "
                    f"{'PROTO':<5} {'ACCEPT':>8} {'REJECT':>8} "
                    f"{'BYTES_OK':>11} {'BYTES_KO':>11}\n")
            f.write("  " + "-" * 100 + "\n")

            for dst, dport, proto, c in sorted(flows, key=lambda x: x[3]["accept"] + x[3]["reject"], reverse=True)[:top]:
                port_str  = f"{dport}({ADMIN_PORTS[dport]})" if dport in ADMIN_PORTS else str(dport)
                proto_str = PROTOCOL_MAP.get(proto, str(proto))
                ext_tag   = " [EXT]" if not is_private(dst) else ""
                f.write(
                    f"  {dst:<18} {svc_label(dst,ip_map)[:38]:<38} {port_str:<12} "
                    f"{proto_str:<5} {c['accept']:>8,} {c['reject']:>8,} "
                    f"{fmt_bytes(c['accept_bytes']):>11} {fmt_bytes(c['reject_bytes']):>11}"
                    f"{ext_tag}\n"
                )
            if len(flows) > top:
                f.write(f"  ... +{len(flows)-top:,} more destinations (raise --top to see them)\n")
            f.write("\n")

        f.write("=" * W + "\n")
        f.write(f"End of detailed report. {len(by_src):,} source IPs.\n")
        f.write("Flow logs contain metadata only — no payload.\n")


# ── Summary report ─────────────────────────────────────────────────────────────

def write_summary(ip_stats: dict, ip_map: dict, out_path: str,
                  lat_thresh: int, rej_thresh: int) -> None:
    """
    CSV: one row per IP sorted by total traffic descending.
    Flagged IPs have max_severity and pipe-joined findings populated.
    Bytes columns are raw integers for easy downstream processing.
    """
    all_sorted = sorted(
        ip_stats.items(),
        key=lambda kv: (kv[1]["in_accept"] + kv[1]["in_reject"] +
                        kv[1]["out_accept"] + kv[1]["out_reject"]),
        reverse=True,
    )

    FIELDS = [
        "ip", "service_label", "type",
        "in_accepted", "in_rejected", "in_bytes",
        "out_accepted", "out_rejected", "out_bytes",
        "flagged", "max_severity", "findings",
    ]

    with open(out_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writeheader()
        for ip, stat in all_sorted:
            info    = ip_map.get(ip)
            label   = info["name"] if info else ip
            stype   = info["type"] if info else ("EXT" if not is_private(ip) else "INT")
            flags   = get_flags(stat, lat_thresh, rej_thresh)
            max_sev = (
                "HIGH"   if any(s == "HIGH"   for s, _ in flags) else
                "MEDIUM" if any(s == "MEDIUM" for s, _ in flags) else ""
            )
            writer.writerow({
                "ip":            ip,
                "service_label": label,
                "type":          stype,
                "in_accepted":   stat["in_accept"],
                "in_rejected":   stat["in_reject"],
                "in_bytes":      stat["in_bytes"],
                "out_accepted":  stat["out_accept"],
                "out_rejected":  stat["out_reject"],
                "out_bytes":     stat["out_bytes"],
                "flagged":       "Y" if flags else "N",
                "max_severity":  max_sev,
                "findings":      " | ".join(msg for _, msg in flags),
            })


# ── Mapping report ─────────────────────────────────────────────────────────────

def write_mapping(pair_stats: dict, ip_map: dict, out_path: str) -> None:
    """
    One row per (src, dst) IP pair — accepted and rejected counts aggregated
    across all ports and protocols for that pair.
    """
    mapping: dict = defaultdict(lambda: {"accept": 0, "reject": 0})
    for (src, dst, _dport, _proto), counts in pair_stats.items():
        mapping[(src, dst)]["accept"] += counts["accept"]
        mapping[(src, dst)]["reject"] += counts["reject"]

    rows = sorted(
        mapping.items(),
        key=lambda kv: kv[1]["accept"] + kv[1]["reject"],
        reverse=True,
    )

    W = 120
    with open(out_path, "w") as f:
        f.write("=" * W + "\n")
        f.write("VPC FLOW LOG — SOURCE-TO-DESTINATION IP MAPPING\n")
        f.write(f"Unique (src, dst) pairs: {len(rows):,}\n")
        f.write("=" * W + "\n\n")

        f.write(
            f"{'SOURCE IP':<18} {'DESTINATION IP':<18} "
            f"{'SRC SERVICE':<35} {'DST SERVICE':<35} "
            f"{'ACCEPTED':>10} {'REJECTED':>10} {'TOTAL':>10}\n"
        )
        f.write("-" * W + "\n")

        for (src, dst), counts in rows:
            accept = counts["accept"]
            reject = counts["reject"]
            total  = accept + reject
            f.write(
                f"{src:<18} {dst:<18} "
                f"{svc_label(src, ip_map)[:35]:<35} {svc_label(dst, ip_map)[:35]:<35} "
                f"{accept:>10,} {reject:>10,} {total:>10,}\n"
            )

        f.write("\n" + "=" * W + "\n")
        f.write(f"End of mapping report. {len(rows):,} unique source-destination pairs.\n")


# ── Security review report ─────────────────────────────────────────────────────

def write_security_review(ip_stats: dict, ip_map: dict, out_path: str,
                           egress_threshold: int, reject_threshold: int) -> None:
    """
    CSV: one row per flagged IP (high egress volume and/or high egress failures).
    IPs meeting both conditions appear first (conditions_met desc, then total egress desc).
    Bytes columns are raw integers; findings are pipe-joined in a single cell.
    """
    flagged = []
    for ip, stat in ip_stats.items():
        reasons = []
        if stat["out_accept"] >= egress_threshold:
            reasons.append(("HIGH",
                f"High egress volume: {stat['out_accept']} accepted outbound flows "
                f"({stat['out_bytes']} bytes sent)"))
        if stat["out_reject"] >= reject_threshold:
            sev = "HIGH" if stat["out_reject"] >= reject_threshold * 5 else "MEDIUM"
            reasons.append((sev,
                f"High egress failures: {stat['out_reject']} rejected outbound flows"))
        if reasons:
            flagged.append((ip, stat, reasons))

    flagged.sort(key=lambda x: (-len(x[2]), -(x[1]["out_accept"] + x[1]["out_reject"])))

    FIELDS = [
        "ip", "service_label", "ip_type", "overall_severity", "conditions_met",
        "egress_accepted", "egress_rejected", "egress_bytes",
        "ingress_accepted", "ingress_rejected", "ingress_bytes",
        "findings",
    ]

    with open(out_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writeheader()
        for ip, stat, reasons in flagged:
            info    = ip_map.get(ip)
            label   = f"{info['name']} [{info['type']}]" if info else ip
            ip_type = info["type"] if info else ("EXT" if not is_private(ip) else "INT")
            overall = "HIGH" if any(s == "HIGH" for s, _ in reasons) else "MEDIUM"
            writer.writerow({
                "ip":               ip,
                "service_label":    label,
                "ip_type":          ip_type,
                "overall_severity": overall,
                "conditions_met":   len(reasons),
                "egress_accepted":  stat["out_accept"],
                "egress_rejected":  stat["out_reject"],
                "egress_bytes":     stat["out_bytes"],
                "ingress_accepted": stat["in_accept"],
                "ingress_rejected": stat["in_reject"],
                "ingress_bytes":    stat["in_bytes"],
                "findings":         " | ".join(msg for _, msg in reasons),
            })


# ── Helpers ────────────────────────────────────────────────────────────────────

def _log(msg: str) -> None:
    print(msg, file=sys.stderr)


def parse_hours(s: str) -> list[int]:
    """Accept '9,10,11' or '9-12' or '0-8,20-23' → sorted list of ints 0-23."""
    result: set = set()
    for part in s.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-", 1)
            result.update(range(int(lo), int(hi) + 1))
        else:
            result.add(int(part))
    bad = [h for h in result if not 0 <= h <= 23]
    if bad:
        sys.exit(f"ERROR: Invalid hours: {bad}. Hours must be 0–23.")
    return sorted(result)


# ── Main ───────────────────────────────────────────────────────────────────────

def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--region",   required=True,
                    help="AWS region of the flow logs, e.g. us-east-1")
    ap.add_argument("--date",     required=True,
                    help="Date to analyze: YYYY-MM-DD")
    ap.add_argument("--hours",    default=None,
                    help="Hours to analyze: '9-12', '0,6,12,18', or omit for all 24.")
    ap.add_argument("--output-prefix", default=None,
                    help="Filename prefix for output files (default: flow_<region>_<date>)")
    ap.add_argument("--lateral-threshold", type=int, default=3,
                    help="Min distinct internal IPs on an admin port to flag (default 3)")
    ap.add_argument("--reject-threshold",  type=int, default=50,
                    help="Min rejected egress flows to flag a reject storm (default 50)")
    ap.add_argument("--top",  type=int, default=25,
                    help="Max destination rows per source in the detailed report (default 25)")
    ap.add_argument("--no-discovery", action="store_true",
                    help="Skip EC2/ECS/RDS service discovery (faster, raw IPs only)")
    ap.add_argument("--egress-threshold", type=int, default=1000,
                    help="Min accepted egress flows to flag high egress volume in security review (default 1000)")
    args = ap.parse_args()

    if not re.match(r"^\d{4}-\d{2}-\d{2}$", args.date):
        ap.error("--date must be YYYY-MM-DD")

    hours  = parse_hours(args.hours) if args.hours else list(range(24))
    prefix = args.output_prefix or f"flow_{args.region}_{args.date.replace('-', '')}"
    if args.hours:
        h_tag = args.hours.replace(",", "-").replace(" ", "")
        prefix += f"_h{h_tag}"

    run_ts  = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    out_dir = os.path.join("Report", run_ts)
    os.makedirs(out_dir, exist_ok=True)

    detail_path      = os.path.join(out_dir, f"{prefix}_detailed.txt")
    summary_path     = os.path.join(out_dir, f"{prefix}_summary.csv")
    mapping_path     = os.path.join(out_dir, f"{prefix}_mapping.txt")
    security_path    = os.path.join(out_dir, f"{prefix}_securityReview.csv")

    _log("=" * 60)
    _log(f"Region:  {args.region}")
    _log(f"Date:    {args.date}")
    _log(f"Hours:   {hours if len(hours) < 24 else 'all 24'}")
    _log(f"Out dir: {out_dir}")
    _log("=" * 60)

    # Credentials
    _log("\nVerifying AWS credentials ...")
    try:
        account_id = get_account_id()
        _log(f"Account: {account_id}")
    except Exception as e:
        sys.exit(f"ERROR: Cannot authenticate: {e}")

    # S3 discovery
    _log("Discovering flow log S3 destination ...")
    bucket, base_prefix = discover_flow_log_s3(args.region)
    _log(f"Bucket:  s3://{bucket}/{base_prefix}")

    s3_prefixes = build_s3_prefixes(bucket, base_prefix, account_id, args.region, args.date, hours)
    _log(f"Scanning {len(s3_prefixes)} hour prefix(es).")

    # Service discovery
    ip_map: dict = {}
    if not args.no_discovery:
        _log("\nRunning service discovery ...")
        ip_map = discover_services(args.region)

    # Download → aggregate → delete
    tmp_dir = tempfile.mkdtemp(prefix="vpc_flow_")
    _log(f"\nTemp dir: {tmp_dir}  (auto-deleted on completion)")
    try:
        record_stream   = stream_parquet_records(s3_prefixes, tmp_dir)
        pair_stats, ip_stats = aggregate(record_stream)
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        _log("Temp files deleted.")

    # Write reports
    _log(f"\nWriting detailed report → {detail_path}")
    write_detailed(pair_stats, ip_stats, ip_map, detail_path,
                   args.lateral_threshold, args.reject_threshold, args.top)

    _log(f"Writing summary report  → {summary_path}")
    write_summary(ip_stats, ip_map, summary_path,
                  args.lateral_threshold, args.reject_threshold)

    _log(f"Writing mapping report  → {mapping_path}")
    write_mapping(pair_stats, ip_map, mapping_path)

    _log(f"Writing security review → {security_path}")
    write_security_review(ip_stats, ip_map, security_path,
                          args.egress_threshold, args.reject_threshold)

    # Console summary
    flagged_n = sum(
        1 for ip, stat in ip_stats.items()
        if get_flags(stat, args.lateral_threshold, args.reject_threshold)
    )
    sec_flagged_n = sum(
        1 for stat in ip_stats.values()
        if stat["out_accept"] >= args.egress_threshold
        or stat["out_reject"] >= args.reject_threshold
    )
    print("\n" + "=" * 60)
    print("Analysis complete.")
    print(f"  Output folder:      {out_dir}")
    print(f"  Unique IPs seen:    {len(ip_stats):,}")
    print(f"  Flagged for review: {flagged_n:,}")
    print(f"  Security flagged:   {sec_flagged_n:,}")
    print(f"  Detailed report:    {detail_path}")
    print(f"  Summary report:     {summary_path}")
    print(f"  Mapping report:     {mapping_path}")
    print(f"  Security review:    {security_path}")
    print("=" * 60)


if __name__ == "__main__":
    main()
