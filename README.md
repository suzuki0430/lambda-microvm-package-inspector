# Lambda MicroVM Package Inspector

Amazon EKSを実行基盤ではなくコントロールプレーンとして使い、ACKの`Microvm` Custom Resourceから検査ごとにAWS Lambda MicroVMを払い出す技術デモです。MVPは、イメージへ事前格納した2つの無害なnpmパッケージだけを対象にします。

久しぶりに作業を再開するときは、目的・期待結果・安全な再開手順をまとめた[PROJECT_STATUS.md](PROJECT_STATUS.md)から確認してください。

- `@demo/good@1.0.0`: lifecycle scriptを持たない比較用パッケージ
- `@demo/canary@1.0.0`: `/tmp`書き込み、子プロセス、ダミー環境変数参照、`.test`ドメインのDNS/HTTP試行、存在しないAWS credentialsパス参照を行う無害なfixture

これはマルウェア解析製品でも、安全性を証明するスキャナーでもありません。取得できた有限の証拠を、再現可能なデモ用ルールで説明するものです。

## 何が実装されているか

```text
trusted control plane (EKS)                  untrusted data plane

PackageInspection CR
        |
        v
Go Orchestrator ------ creates ------> ACK Microvm CR
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
        ^                                  |
        +----------------------------------+
        |
        +-- JSON Schema validation -> rule-based risk -> S3 JSON/Markdown
        +-- delete ACK Microvm CR -> ACK terminates MicroVM
```

主な実装は次のディレクトリに分かれています。

- `runner/`: Python製の静的・動的検査runnerとHTTP API
- `controller/`: Go/controller-runtime製Orchestrator、risk engine、S3 store
- `infra/`: AWS CDK TypeScript（EKS、S3、ECR、MicroVM Image、deny-egress VPC connector、IAM）
- `packages/`: 良性fixtureとcanary fixture
- `api/`: `PackageInspection` CRDの元になるGo APIとreport JSON Schema
- `deploy/`: CRD、最小RBAC、controller Deployment、デモCR

詳細は[アーキテクチャ](docs/architecture.md)、[脅威モデル](docs/threat-model.md)、[制約](docs/limitations.md)を参照してください。

## ローカルで試す

必要なローカルツールはNode.js 20以上、pnpm 10.11、Python 3.11以上、uv、Go 1.25.12 toolchain、Dockerです。

```bash
make fixtures
make test
make security-audit
make runner-scan-good
make runner-scan-canary
```

Linux/arm64コンテナで`strace`を含む実経路を確認する場合は次を実行します。

```bash
make runner-integration
```

macOS上のrunner単体テストでは`strace`が使えません。DockerまたはLambda MicroVMでのみsyscall由来のprocess/file/network証拠が追加されます。

## AWSへデプロイする

AWS操作の前に[デプロイ手順](docs/deployment.md)、[AWS技術スパイク](docs/aws-spikes.md)、[脅威モデル](docs/threat-model.md)を読んでください。専用の非本番アカウントを前提とします。

```bash
export AWS_PROFILE=REPLACE_WITH_DEMO_PROFILE
export AWS_REGION=us-east-1
export AWS_DEFAULT_REGION="$AWS_REGION"
export EXPECTED_AWS_ACCOUNT_ID=REPLACE_WITH_12_DIGIT_ACCOUNT_ID

./scripts/preflight
AWS_REGION="$AWS_REGION" \
MICROVM_BASE_IMAGE_VERSION=PRECHECKED_VERSION \
./scripts/deploy-infrastructure
AWS_REGION="$AWS_REGION" ./scripts/deploy-controller
./scripts/run-demo
```

`PackageInspection`のstatusには、生ログではなくphase、risk summary、S3 URI、SHA-256だけを保存します。JWEはKubernetesへ永続化せず、必要なリクエストごとに5分・port 8080限定で生成します。

## 必ず後片付けする

`PackageInspection` finalizerは、対応するACK `Microvm` CRが消えるまでユーザーCRの削除を完了させません。さらにAWS側の残存VMを確認してからCDK stackを削除します。

```bash
CONFIRM_DESTROY=LambdaMicrovmPackageInspector \
AWS_REGION="$AWS_REGION" \
./scripts/destroy-demo
```

スタックにはNAT Gateway、EKS control plane、EC2 managed node、Lambda MicroVM Imageなど費用が発生するリソースが含まれます。記事撮影後は当日中の削除を推奨します。

## 安全側の制約

- CRD admissionとrunner catalogの両方で、2つのfixture・version `1.0.0`以外を拒否
- MicroVM execution roleなし、AWS credentialなし、shell ingress connectorなし
- runtime egressはisolated subnet + outbound ruleなしSecurity GroupのVPC connectorへ固定
- package codeはUID/GID 10001、rlimit、wall-clock、stdout/stderr、ファイルサイズ制限付き
- package tarballはsizeとSHA-256を実行前に検証
- 1 MicroVMにつき1 scan IDだけを受理し、Kubernetes UIDで冪等化
- reportを2 MiBで打ち切り、JSON Schema検証後にだけS3へ保存
- controllerは対象namespaceだけをwatchし、redirectと想定外endpoint originを拒否

fixture以外を追加する前にDNS Firewallまたは管理下DNS sinkを導入してください。AmazonProvidedDNSはSecurity Groupだけでは完全に遮断できないため、このMVPを任意の第三者パッケージへ拡張してはいけません。

## ライセンス

[MIT License](LICENSE)
