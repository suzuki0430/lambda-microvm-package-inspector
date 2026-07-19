# Deployment guide

## 前提

- 専用の非本番AWS account
- Lambda MicroVMsとCloudFormation resource typeが利用できるregion
- 有効なAWS credentialとCDK bootstrap済みenvironment
- AWS CLI v2で`lambda-microvms`と`lambda-core` commandが利用可能
- Node.js 20以上、pnpm 10.11、uv、Go 1.25.12 toolchain、Docker buildx、kubectl、jq
- EKS、NAT Gateway、EC2、S3、ECR、IAM、Lambda MicroVM、VPC connectorを作成できる権限

このrepositoryの既定regionは公式例に合わせて`us-east-1`です。別regionを使う場合は、preflightでmanaged MicroVM imageが返ることを必ず確認してください。

## 1. read-only preflight

```bash
export AWS_REGION=us-east-1
export AWS_DEFAULT_REGION="$AWS_REGION"
./scripts/preflight
```

preflightが表示したmanaged `al2023-1` versionを環境変数へ設定します。deploy scriptは明示値がなければ停止するため、`infra/cdk.json`のsynth用既定値`1.0`を誤ってAWSへdeployしません。

```bash
export MICROVM_BASE_IMAGE_VERSION=REPLACE_WITH_DISCOVERED_VERSION
cd infra
pnpm cdk synth -c "microvmBaseImageVersion=$MICROVM_BASE_IMAGE_VERSION"
```

## 2. infrastructure

```bash
AWS_REGION=us-east-1 \
MICROVM_BASE_IMAGE_VERSION="$MICROVM_BASE_IMAGE_VERSION" \
./scripts/deploy-infrastructure
```

CDKは次を作ります。

- 2 AZ VPC（public、EKS private-with-egress、MicroVM isolated subnet）
- NAT Gateway 1台、EKS 1.33、arm64 managed node 1台
- outboundなしSecurity GroupとLambda Network Connector
- encrypted/versioned/private S3 report bucket
- MicroVM build artifactと`AWS::Lambda::MicrovmImage`
- ACK 0.1.1 Helm release（`Microvm`だけ、namespace scope、deletion policy delete）
- ACK/Orchestrator用の別々のIRSA service account
- controller image用ECR repository

MicroVM execution roleとshell ingress connectorは作りません。

`AWS::Lambda::MicrovmImage`のbuildでは、digest固定したNode base imageと`python3`/`strace`を取得するためAWS管理の`INTERNET_EGRESS` connectorを使います。検査実行時のACK `Microvm` CRには、このbuild用connectorではなくCDKが作成したdeny-egress connectorだけを設定します。

## 3. controller

```bash
AWS_REGION=us-east-1 \
CONTROLLER_IMAGE_TAG="$(git rev-parse --short=12 HEAD)" \
./scripts/deploy-controller
```

scriptはGo controllerをlinux/arm64でbuild/pushし、CRD、最小RBAC、report Schema ConfigMap、Deploymentを適用します。tagを省略した場合も時刻ベースの一意tagを使い、node上の古い`demo` imageを再利用しません。完了後に確認します。

```bash
kubectl -n package-inspector-system get pods
kubectl get crd microvms.lambdamicrovms.services.k8s.aws
kubectl get crd packageinspections.inspection.demo.aws
```

## 4. demo

```bash
./scripts/run-demo
kubectl -n package-inspector-system get packageinspections -o yaml
```

期待値は、両方が`Succeeded`になり、goodよりcanaryのfinding数・scoreが大きく、canaryにlifecycle、process、`/tmp`、DNS、network、credential path evidenceが含まれることです。S3のJSON report SHA-256とCR statusのSHA-256が一致することも確認します。

## 5. failure drill

検査中にCRを削除し、finalizerがMicroVMを片付けることを確認します。

```bash
kubectl -n package-inspector-system delete packageinspection canary-package
AWS_REGION=us-east-1 ./scripts/verify-cleanup
```

ACK/IAM障害でfinalizerが止まった場合、finalizerを手で外す前にAWS CLIで該当MicroVMをterminateしてください。先にfinalizerだけを削除すると課金resourceを孤児化します。

## 6. destroy

```bash
CONFIRM_DESTROY=LambdaMicrovmPackageInspector \
AWS_REGION=us-east-1 \
./scripts/destroy-demo
```

scriptは全`PackageInspection`を削除し、active/suspended/terminating MicroVMが0であることを確認してからCDK destroyします。Network Connectorは使用中のMicroVMがあると削除できません。
