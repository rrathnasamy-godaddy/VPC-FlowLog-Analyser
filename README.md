# vpc_flow_analyzer.py

Self-contained VPC Flow Log analyzer that reads Parquet files directly from S3, detects lateral movement patterns, and produces four structured text reports. No LLM required — pure Python with `boto3` and `pyarrow`.

All reports are written to `Report/<YYYY-MM-DD_HH-MM-SS>/` — a new timestamped subfolder is created on every scan run so historical results are never overwritten.

## Requirements

```bash
pip3 install boto3 pyarrow
```

The AWS CLI must also be installed and on your `PATH` (used internally to stream Parquet files from S3).

## AWS Credentials

Any standard AWS credential mechanism works:

| Method | Environment variables |
|---|---|
| Named profile | `AWS_PROFILE` |
| Static keys | `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` |
| Temporary credentials | Above + `AWS_SESSION_TOKEN` |

`--region` overrides `AWS_DEFAULT_REGION`.

## Required IAM Permissions

```json
{
  "Effect": "Allow",
  "Action": [
    "sts:GetCallerIdentity",
    "ec2:DescribeFlowLogs",
    "s3:ListBucket",
    "s3:GetObject",
    "ec2:DescribeInstances",
    "ecs:ListClusters",
    "ecs:ListTasks",
    "ecs:DescribeTasks",
    "rds:DescribeDBInstances"
  ],
  "Resource": "*"
}
```

`ec2:DescribeInstances`, `ecs:*`, and `rds:DescribeDBInstances` are only needed when service discovery is enabled (the default). Use `--no-discovery` to skip them.

## Usage

```bash
# Analyze all 24 hours for a date
python3 vpc_flow_analyzer.py --region us-east-1 --date 2026-09-23

# Analyze a specific hour range (inclusive)
python3 vpc_flow_analyzer.py --region us-east-1 --date 2026-09-23 --hours 9-12

# Analyze specific hours (comma-separated)
python3 vpc_flow_analyzer.py --region us-east-1 --date 2026-09-23 --hours 0,6,12,18

# Skip EC2/ECS/RDS discovery (faster, shows raw IPs only)
python3 vpc_flow_analyzer.py --region us-east-1 --date 2026-09-23 --hours 9-12 --no-discovery
```

## All Options

| Flag | Default | Description |
|---|---|---|
| `--region` | *(required)* | AWS region where flow logs are configured |
| `--date` | *(required)* | Date to analyze in `YYYY-MM-DD` format |
| `--hours` | all 24 | Hour range: `9-12`, `0,6,12,18`, or omit for full day |
| `--output-prefix` | `flow_<region>_<date>` | Filename prefix for output files |
| `--lateral-threshold` | `3` | Min distinct internal IPs on an admin port to flag fan-out |
| `--reject-threshold` | `50` | Min rejected egress flows to flag a reject storm |
| `--top` | `25` | Max destination rows per source IP in the detailed report |
| `--no-discovery` | off | Skip EC2/ECS/RDS service label lookup |
| `--egress-threshold` | `1000` | Min accepted egress flows to flag high egress volume in the security review |

## Output Files

Four files are written to `Report/<YYYY-MM-DD_HH-MM-SS>/` each time the script runs. The timestamp comes from the local clock at scan start, so each run gets its own folder and no previous results are overwritten.

```
Report/
└── 2026-09-25_14-30-22/
    ├── flow_us-east-1_20260925_detailed.txt
    ├── flow_us-east-1_20260925_summary.csv
    ├── flow_us-east-1_20260925_mapping.txt
    └── flow_us-east-1_20260925_securityReview.csv
```

### `<prefix>_securityReview.csv`

One row per flagged IP. An IP is included if it meets at least one condition:

| Condition | Severity |
|---|---|
| `accepted egress flows ≥ egress-threshold` | HIGH |
| `rejected egress flows ≥ 5 × reject-threshold` | HIGH |
| `rejected egress flows ≥ reject-threshold` | MEDIUM |

IPs meeting **both** conditions appear first (`conditions_met` = 2), then single-condition matches sorted by total egress volume.

Columns:

| Column | Description |
|---|---|
| `ip` | IP address |
| `service_label` | EC2/ECS/RDS name and type, or raw IP |
| `ip_type` | EC2 / ECS / RDS / INT / EXT |
| `overall_severity` | HIGH or MEDIUM (highest across all findings for this IP) |
| `conditions_met` | Number of flag conditions triggered (1 or 2) |
| `egress_accepted` | Accepted outbound flow count |
| `egress_rejected` | Rejected outbound flow count |
| `egress_bytes` | Bytes sent on accepted outbound flows (raw integer) |
| `ingress_accepted` | Accepted inbound flow count |
| `ingress_rejected` | Rejected inbound flow count |
| `ingress_bytes` | Bytes received on accepted inbound flows (raw integer) |
| `findings` | Pipe-separated finding descriptions |

### `<prefix>_summary.csv`

One row per IP, sorted by total traffic (accepted + rejected, in + out) descending. All IPs appear; flagged ones are marked in-place rather than in a separate section.

Columns:

| Column | Description |
|---|---|
| `ip` | IP address |
| `service_label` | EC2/ECS/RDS name, or raw IP if unknown |
| `type` | EC2 / ECS / RDS / INT / EXT |
| `in_accepted` | Accepted inbound flow count |
| `in_rejected` | Rejected inbound flow count |
| `in_bytes` | Bytes received on accepted inbound flows (raw integer) |
| `out_accepted` | Accepted outbound flow count |
| `out_rejected` | Rejected outbound flow count |
| `out_bytes` | Bytes sent on accepted outbound flows (raw integer) |
| `flagged` | `Y` if any lateral-movement rule fired, otherwise `N` |
| `max_severity` | HIGH, MEDIUM, or empty |
| `findings` | Pipe-separated finding descriptions (empty if not flagged) |

### `<prefix>_mapping.txt`

One row per unique (source IP, destination IP) pair, sorted by total flow count descending. Columns:

| Column | Description |
|---|---|
| SOURCE IP | Originating IP address |
| DESTINATION IP | Target IP address |
| SRC SERVICE | EC2/ECS/RDS label for the source (or raw IP if unknown) |
| DST SERVICE | EC2/ECS/RDS label for the destination (or raw IP if unknown) |
| ACCEPTED | Total accepted flows across all ports and protocols for this pair |
| REJECTED | Total rejected flows across all ports and protocols for this pair |
| TOTAL | ACCEPTED + REJECTED |

Every (src, dst) combination seen in the flow logs appears exactly once. Use this file to quickly understand which systems are communicating and the accept/reject ratio between any two IPs.

### `<prefix>_detailed.txt`

One section per source IP, sorted with flagged IPs first. Each section shows:
- Egress/ingress accept and reject counts with byte totals
- Per-destination table: destination IP, service label, port, protocol, accept/reject counts, bytes
- Flag markers (`[HIGH]` / `[MEDIUM]`) inline if the source triggered a detection rule

### `<prefix>_summary.txt`

**Section 1** — all IPs sorted by total traffic volume with inline flag columns.

**Section 2** — IPs requiring review, each with a plain-English explanation of the finding and full traffic breakdown.

## Detection Rules

| Severity | Condition |
|---|---|
| HIGH | An internal IP connects (ACCEPT) to `≥ lateral-threshold` distinct internal IPs on an admin port |
| MEDIUM | An internal IP attempts (REJECT) to reach `≥ lateral-threshold` distinct internal IPs on an admin port |
| HIGH/MEDIUM | An IP generates `≥ reject-threshold` rejected egress flows to `≥ 2×lateral-threshold` distinct destinations (reject storm) |

### Monitored Admin Ports

SSH (22), Telnet (23), RDP (3389), WinRM (5985/5986), SMB (445), MSRPC (135), NetBIOS (139), NFS (2049), PostgreSQL (5432), MySQL (3306), MSSQL (1433), MongoDB (27017), Redis (6379), Elasticsearch (9200), ZooKeeper (2181), Consul (8500), SaltStack (4505/4506), Prometheus (9090), NodeExporter (9100).

## How It Works

1. **Credential check** — calls `sts:GetCallerIdentity` to validate the session.
2. **Flow log discovery** — calls `ec2:DescribeFlowLogs` to find the S3 bucket and key prefix automatically. Exits with a diagnostic message if none is found.
3. **Service discovery** (optional) — maps private and public IPs to EC2 instance names, ECS task definitions, and RDS identifiers for human-readable labels in reports.
4. **Streaming download** — lists and downloads Parquet files one at a time from the Hive-style S3 partition layout (`AWSLogs/aws-account-id=.../year=.../month=.../day=.../hour=.../`). Each file is deleted after processing, so peak disk usage equals the size of a single file.
5. **Aggregation** — accumulates per-pair (src, dst, port, protocol) and per-IP statistics in memory.
6. **Report generation** — creates `Report/<timestamp>/`, then writes all four reports and prints a console summary with the output folder path and flagged IP counts.

## Notes

- VPC Flow Logs contain metadata only — no packet payload is captured or stored.
- All detections are heuristic leads. Corroborate findings with GuardDuty, CloudTrail, and host-level logs before taking any containment action.
- The script requires an active S3 flow log destination in the target region. CloudWatch Logs destinations are not supported.
- If the Hive-style partition layout differs from the default AWS format, use `--output-prefix` as a workaround or adjust `build_s3_prefixes` in the source.
