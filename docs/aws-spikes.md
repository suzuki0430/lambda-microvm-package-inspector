# AWS technical spikes

ローカル実装の成功と、Previewサービス上での成立は分けて扱います。以下を専用の非本番accountで順に確認し、前段が成功するまでEKSを作成しません。

| 優先度 | 検証 | 成功条件 | 現在の状態 |
| --- | --- | --- | --- |
| P0 | account/region entitlement | `list-managed-microvm-images`とversion一覧が返る | 要AWS検証 |
| P0 | CloudFormation contract | `AWS::Lambda::MicrovmImage`と`AWS::Lambda::NetworkConnector`がregionで利用可能 | CDK synthのみ成功 |
| P0 | build/runtime network split | image buildは`INTERNET_EGRESS`で成功し、実行時CRはdeny-egress connectorだけを持つ | CDK assertion成功、AWSは要検証 |
| P0 | guest observer | Lambda MicroVM内でroot observerの`strace -ff`がUID 10001のnpm processを追跡できる | Linux/arm64 Dockerでは成功、AWSは要検証 |
| P0 | ingress JWE | `CreateMicrovmAuthToken`の5分・port 8080 tokenでrunner APIだけへ到達できる | client contract testのみ成功 |
| P0 | ACK contract | chart `0.1.1`の`Microvm` CRD field/status名が生成manifestと一致する | source準拠、実clusterは要検証 |
| P0 | cleanup | CR削除後にACK CRとAWS MicroVMが消え、connector削除を妨げない | controller unit testのみ成功 |
| P1 | DNS behavior | `.test`問い合わせの観測結果とAmazonProvidedDNSの残余経路を記録する | 要AWS検証 |
| P1 | cost/time | image build、EKS起動、scan、cleanupの時間と概算費用を記録する | 要AWS検証 |

## 実行順

1. `AWS_REGION=us-east-1 ./scripts/preflight`を実行する。これは読み取り専用である。
2. managed base imageの実versionを`infra/cdk.json`またはCDK contextへ固定する。
3. CDK stack全体ではなく、可能ならMicroVM image/network connectorだけの一時stackでP0 buildを確認する。
4. EKS/ACKを作り、good fixtureを1回だけ実行する。
5. canaryを実行し、S3 reportと`kubectl` statusを保存する。
6. failure drillを行い、AWS CLIとKubernetesの両方でMicroVMが0であることを確認する。

AWS側でfield名やlifecycle semanticsが異なる場合、推測でcompatibility shimを追加せず、実際にinstallされたACK CRDとCloudFormation schemaをfixtureとして保存してから実装を更新します。
