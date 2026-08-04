# Project status and safe resume guide

## Goal

This repository demonstrates isolated npm package inspection in disposable AWS Lambda MicroVMs. Amazon EKS is the trusted control plane: a Go orchestrator creates an ACK `Microvm` Custom Resource, receives a bounded report from the MicroVM runner, validates and scores it, stores JSON and Markdown in S3, and then confirms MicroVM termination.

This is a technical demo, not a malware analysis product and not proof that a package is safe.

## Expected demo result

| Inspection | Expected phase | Expected risk | Expected policy result |
| --- | --- | --- | --- |
| `@demo/good@1.0.0` | `Succeeded` | `low` | `0/100`, no demo rules matched |
| `@demo/canary@1.0.0` | `Succeeded` | `critical` | `95/100`, seven demo rules matched |

The canary should produce evidence for an npm lifecycle script, suspicious static patterns, a child process, a credential-path access attempt, DNS and HTTP connection attempts, and a dummy environment-variable read. Runtime egress is denied; the evidence demonstrates attempted behavior, not successful exfiltration.

Both reports retain the runner's deterministic `python -> npm` startup events as evidence. Policy evaluation excludes only those two trusted harness commands so they do not create a false-positive child-process finding for the good fixture.

## Repository state

- Infrastructure: AWS CDK in TypeScript, EKS 1.34, one on-demand `t4g.medium` ARM node
- Orchestrator: Go and controller-runtime
- Guest runner: Python, non-root npm execution, `strace`, rlimits, bounded output
- AWS integration: ACK Lambda MicroVMs controller, S3 reports, ECR controller image, CloudWatch Logs
- Fixtures: only `@demo/good@1.0.0` and `@demo/canary@1.0.0`

AWS is external state and this file is not evidence of what is currently deployed. Always authenticate and query the target account before acting.

## Resume checklist

```bash
export AWS_PROFILE=REPLACE_WITH_DEMO_PROFILE
export AWS_REGION=us-east-1
export AWS_DEFAULT_REGION="$AWS_REGION"
export EXPECTED_AWS_ACCOUNT_ID=REPLACE_WITH_12_DIGIT_ACCOUNT_ID

aws sso login --profile "$AWS_PROFILE"
aws sts get-caller-identity
./scripts/preflight
git status --short
make test
make security-audit
```

Record the managed `al2023-1` version printed by `preflight`, then follow [the deployment guide](docs/deployment.md). Every mutating script checks `EXPECTED_AWS_ACCOUNT_ID` before changing AWS or Kubernetes state.

## Evidence to keep

- `kubectl get packageinspections` showing the good/canary phase, risk, and score
- Lambda MicroVM image and Network Connector states
- S3 `report.json` and `report.md` objects plus `report-sha256` metadata
- `./scripts/verify-cleanup` showing no active or suspended MicroVMs

## Mandatory cleanup

```bash
CONFIRM_DESTROY=LambdaMicrovmPackageInspector \
AWS_REGION="$AWS_REGION" \
./scripts/destroy-demo
```

Do not remove Kubernetes finalizers before terminating the corresponding AWS MicroVM. The EKS control plane, NAT Gateway, EC2 node, and MicroVM resources can incur charges while they remain deployed.
