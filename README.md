# Lambda MicroVM Package Inspector

This technical demo uses Amazon EKS as a control plane rather than an execution environment. For each inspection, it provisions a fresh AWS Lambda MicroVM through an AWS Controllers for Kubernetes (ACK) `Microvm` custom resource. The MVP accepts only two harmless npm packages that are preloaded into the MicroVM image.

If you are returning to the project after a break, start with [PROJECT_STATUS.md](PROJECT_STATUS.md). It summarizes the goal, expected results, and safe steps for resuming work.

- `@demo/good@1.0.0`: a comparison package with no lifecycle scripts
- `@demo/canary@1.0.0`: a harmless fixture that writes to `/tmp`, starts a child process, reads a dummy environment variable, attempts DNS and HTTP access to a `.test` domain, and tries to open a nonexistent AWS credentials path

This is neither a malware analysis product nor a scanner that proves a package is safe. It records a limited set of observations and explains them using deterministic rules written for this demo.

## What is implemented

```text
trusted control plane (EKS)                             untrusted data plane

PackageInspection CR
        |
        | watch
        v
custom Go controller ---- creates ------> ACK Microvm CR
        |                                      |
        |                                      | watch
        |                                      v
        |                               AWS ACK controller
        |                                      |
        | CreateMicrovmAuthToken               | RunMicrovm / Get / Terminate
        | (JWE, port 8080, 5 min)               v
        +------------------------------> Lambda MicroVM
                                               |
                                               | Python supervisor (trusted)
                                               |   -> static archive inspection
                                               |   -> strace + rlimits
                                               |   -> npm install as UID 10001
                                               v
                                          JSON report
        ^                                      |
        +--------------------------------------+
        |
        +-- JSON Schema validation -> rule-based risk -> S3 JSON/Markdown
        +-- delete ACK Microvm CR -> ACK terminates MicroVM
```

The main components are organized into the following directories:

- `runner/`: Python static and dynamic inspection runner and its HTTP API
- `controller/`: Go/controller-runtime orchestrator, risk engine, and S3 report store
- `infra/`: AWS CDK in TypeScript for EKS, S3, ECR, the MicroVM image, the deny-egress VPC connector, and IAM
- `packages/`: the benign comparison fixture and the canary fixture
- `api/`: the Go API behind the `PackageInspection` CRD and the report JSON Schema
- `deploy/`: the CRD, minimal RBAC, controller Deployment, and example custom resources

See [Architecture](docs/architecture.md), [Threat model](docs/threat-model.md), and [Limitations](docs/limitations.md) for details.

## How an inspection starts on AWS

An inspection starts when a `PackageInspection` custom resource (CR) is created in the watched namespace. The current implementation is not connected to EventBridge, cron, SQS, npm publication events, or any other external trigger. `./scripts/run-demo` applies these two inspection requests with `kubectl`:

- `deploy/examples/good.yaml`: inspects `@demo/good@1.0.0`
- `deploy/examples/canary.yaml`: inspects `@demo/canary@1.0.0`

Neither file contains a package artifact. Each is a `PackageInspection` CR that specifies the ecosystem, package name, version, and timeout. The custom Go controller watches these resources and orchestrates the inspection workflow.

The two controllers have different responsibilities:

- **Custom Go controller**: validates the `PackageInspection` and creates an ACK `Microvm` CR. After the MicroVM reaches `RUNNING`, it sends `POST /v1/scans` to the runner, waits for completion, retrieves and validates the report, stores it in S3, and deletes the `Microvm` CR.
- **AWS ACK controller**: watches the `Microvm` CR created by the custom controller and calls the Lambda MicroVMs API to run, query, and terminate the actual MicroVM.

In short, the custom Go controller creates the ACK `Microvm` CR, while the AWS ACK controller operates the MicroVM in AWS.

## When fixtures are added to the MicroVM image

The good and canary fixtures are not downloaded from the npm registry during an inspection. Before deploying the CDK stack, `./scripts/deploy-infrastructure` invokes `scripts/prepare-microvm-artifact`, which packages them into the MicroVM image as follows:

1. `scripts/build-fixtures` generates the good and canary `.tgz` files and their catalog.
2. The runner, `fixtures/catalog.json`, and the fixture `.tgz` files are copied to `build/microvm-artifact`.
3. CDK uploads the build artifact to S3 and starts the `AWS::Lambda::MicrovmImage` build.
4. `microvm-image/Dockerfile` copies the fixtures to `/opt/package-inspector/fixtures/`.

Each `PackageInspection` launches a fresh MicroVM from the same image, which already contains the fixtures. If you change a fixture or the runner, run `deploy-infrastructure` again to update the MicroVM image.

## Run locally

The local prerequisites are Node.js 20 or later, pnpm 10.11, Python 3.11 or later, uv, the Go 1.25.12 toolchain, and Docker.

```bash
make fixtures
make test
make security-audit
make runner-scan-good
make runner-scan-canary
```

To exercise the full `strace` path in a Linux/arm64 container, run:

```bash
make runner-integration
```

The runner cannot use `strace` in macOS unit tests. Syscall-derived process, file, and network evidence is available only in Docker or a Lambda MicroVM.

## Deploy to AWS

Before performing any AWS operation, read the [deployment guide](docs/deployment.md), [AWS technical spikes](docs/aws-spikes.md), and [threat model](docs/threat-model.md). Use a dedicated non-production account. The repository default and the example below use `ap-northeast-1`.

```bash
export AWS_PROFILE=REPLACE_WITH_DEMO_PROFILE
export AWS_REGION=ap-northeast-1
export AWS_DEFAULT_REGION="$AWS_REGION"
export EXPECTED_AWS_ACCOUNT_ID=REPLACE_WITH_12_DIGIT_ACCOUNT_ID

./scripts/preflight
AWS_REGION="$AWS_REGION" \
MICROVM_BASE_IMAGE_VERSION=PRECHECKED_VERSION \
./scripts/deploy-infrastructure
AWS_REGION="$AWS_REGION" ./scripts/deploy-controller
./scripts/run-demo
```

The `PackageInspection` status stores only the phase, risk summary, S3 URIs, and SHA-256 digest, not raw evidence. JWE tokens are never persisted in Kubernetes. The controller creates a fresh token for each request, restricted to port 8080 and valid for five minutes.

## Always clean up

The `PackageInspection` finalizer prevents deletion of the user-facing CR from completing until the corresponding ACK `Microvm` CR is gone. The cleanup script also checks for residual MicroVMs in AWS before deleting the CDK stack.

```bash
CONFIRM_DESTROY=LambdaMicrovmPackageInspector \
AWS_REGION="$AWS_REGION" \
./scripts/destroy-demo
```

The stack contains billable resources, including a NAT Gateway, an EKS control plane, an EC2 managed node, and a Lambda MicroVM image. Delete it on the same day after completing the demo or taking screenshots.

## Safety boundaries

- CRD validation and the runner catalog reject anything except the two fixtures at version `1.0.0`.
- The MicroVM has no execution role, AWS credentials, or shell ingress connector.
- Runtime egress is fixed to a VPC connector that uses isolated subnets and a security group with no outbound rules.
- Package code runs as UID/GID 10001 with resource limits for process CPU time, process count, wall-clock time, stdout, stderr, and file size.
- The package tarball size and SHA-256 digest are verified before execution.
- Each MicroVM accepts only one scan ID, with idempotency keyed by the Kubernetes UID.
- Reports are capped at 2 MiB and stored in S3 only after JSON Schema validation.
- The controller watches only the target namespace and rejects redirects and unexpected endpoint origins.

Before adding any package beyond the fixtures, introduce DNS Firewall or a controlled DNS sink. A security group alone cannot completely block AmazonProvidedDNS, so do not extend this MVP to arbitrary third-party packages in its current form.

## License

[MIT License](LICENSE)
