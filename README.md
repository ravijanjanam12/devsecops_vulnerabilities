# Insecure Terraform sample (test fixture for secagent)

⚠️ **Do not deploy.** Every resource in `main.tf` has at least one deliberate
security flaw so you can watch the agent find and fix them.

## Planted issues (what the scanner should catch)

| # | Location | Issue | Severity | CWE |
|---|----------|-------|----------|-----|
| 1 | `provider "aws"` | Hardcoded access/secret keys | critical | CWE-798 |
| 2 | `aws_security_group.web` | SSH (22) open to `0.0.0.0/0` | high | CWE-284 |
| 3 | `aws_security_group.web` | All ports open to `0.0.0.0/0` | critical | CWE-284 |
| 4 | `aws_s3_bucket.data` | `acl = "public-read"` (public bucket) | high | CWE-732 |
| 5 | `aws_s3_bucket.data` | No server-side encryption | medium | CWE-311 |
| 6 | `aws_db_instance.app` | `publicly_accessible = true` | high | CWE-284 |
| 7 | `aws_db_instance.app` | `storage_encrypted = false` | high | CWE-311 |
| 8 | `aws_db_instance.app` | Hardcoded DB password | critical | CWE-798 |
| 9 | `aws_iam_policy.admin` | `Action="*"`, `Resource="*"` | high | CWE-269 |
| 10 | `aws_ebs_volume.data` | `encrypted = false` | medium | CWE-311 |
| 11 | `aws_cloudtrail.main` | Log validation + encryption disabled | medium | CWE-778 |

## How to test

```bash
# 1. Make it a git repo (the agent commits/branches against git)
cd examples/terraform-insecure
git init && git add -A && git commit -m "insecure baseline"

# 2. Scan only — see the findings, no changes
secagent scan .

# 3. Dry run — generate fixes without touching git
secagent remediate . --dry-run --min-severity medium

# 4. Full run — fix and commit to a branch (add a GitHub remote first if you
#    want a real PR opened)
secagent remediate . --min-severity medium --no-pr
git diff HEAD~1   # review what the model changed
```

## What a good fix looks like

- Secrets → replaced with `var.*` references (and a note to set them via
  environment/`TF_VAR_*`, never committed).
- `0.0.0.0/0` on SSH → restricted CIDR or a variable.
- S3 → `acl = "private"` + a `aws_s3_bucket_server_side_encryption_configuration`.
- RDS → `publicly_accessible = false`, `storage_encrypted = true`, password via variable.
- IAM → scoped actions/resources instead of `*`.
- EBS → `encrypted = true`.
- CloudTrail → validation + KMS encryption enabled.

Review every change before applying to real infrastructure — the fixes are
AI-generated.
