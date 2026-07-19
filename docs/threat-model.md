# Threat model

## 保護対象

- AWS accountのIAM権限、credential、請求上限
- EKS API、worker node、controller process、ACK controller
- S3の過去reportとreport integrity
- 同時に存在する別の検査MicroVM
- 操作者の端末とGitHub repository

## 信頼境界

1. ユーザー入力から`PackageInspection` admissionまで
2. EKS control planeからLambda MicroVMのservice-managed HTTPS endpointまで
3. MicroVM内のtrusted observerからUID 10001のnpm lifecycle processまで
4. MicroVMからVPC egress connectorまで
5. untrusted JSON reportからSchema validator/risk engine/S3まで

ACK `Microvm` statusも無条件には信用しません。endpointはHTTPS、portなし、指定regionの`*.lambda-microvm.<region>.on.aws`だけを許可し、redirectを拒否します。

## 攻撃対象と対策

| 攻撃 | MVPの対策 | 残余リスク |
| --- | --- | --- |
| install scriptからAWS credentialを盗む | execution roleなし、runner環境変数allowlist、host mountなし | guest/service固有の未知のcredential経路は要検証 |
| EKS node/他Podを攻撃 | codeは別guest kernel、EKSへnetwork pathなし | Lambda/Firecracker/guest kernel escapeはAWS security boundaryに依存 |
| public Internetへexfiltrate | runtime VPC connectorを必須化し、isolated subnet + outboundなしSG | AmazonProvidedDNSはSGだけで完全遮断できない |
| 任意packageを投入する | CRD enum + controller allowlist + runner catalogの三重制約 | repository contributorがfixtureを変更するsupply-chain risk |
| artifactを差し替える | catalogのsize/SHA-256を毎回検証 | image build時のbase image/container registryを信頼 |
| build時のsupply chain | container baseはmanifest digest固定、build roleを分離 | Debian repository packageはversion固定しておらず、trusted buildにはInternet egressがある |
| process/file/output bomb | timeout、RLIMIT_NPROC/NOFILE/FSIZE、bounded capture、2 MiB report | guest全体のdisk inodeやkernel memory枯渇は完全には制御しない |
| symlink/path traversal | tarを展開せずentryを検査、npmへ検証済みtgzだけ渡す | npm自身の未知の展開脆弱性 |
| reportでcontrollerを攻撃 | response上限、JSON Schema、typed projection、Markdown escape、生stdoutをMarkdownへ載せない | JSON parser/schema libraryの未知の脆弱性 |
| reconcile retryで複数実行 | Kubernetes UIDをscan IDにし、runnerが同一IDを冪等受理 | status更新前の通信結果は再pollまで遅れる |
| cleanup失敗で課金継続 | PackageInspection finalizer、ACK deletion policy、最大duration、cleanup verification script | ACK停止やIAM障害時は手動terminateが必要 |
| JWE漏えい | 5分、port 8080限定、Kubernetes/S3/logへ保存しない | 有効期間内にcontroller memoryから盗まれれば利用可能 |
| CR大量作成による課金 | reconcile concurrency 1、CR最大10・Microvm CR最大2のResourceQuota | 削除と再作成を繰り返すrate/budget attackは防がない |

## 想定攻撃者

- package archiveとinstall scriptを制御する攻撃者
- `PackageInspection`を作れるnamespace利用者
- report内の全フィールドを細工できる侵害済みrunner

namespace利用者はfixtureの2座標しか選べません。任意URL、command、environment、image ARN、egress connector、execution roleは指定できません。

## 対象外

- malware family判定、完全なdeobfuscation、sleep/evasion対策
- kernel exploitやMicroVM escapeの実証・検出
- native addonの完全解析、encrypted payload解析
- npm registryから任意packageを安全にmirrorするpipeline
- DNS Firewall、HTTP sink、PCAP、eBPF、Strands/LLM説明
- multi-tenant production SLA、quota制御、admission認可product
- 「低riskなら安全」という保証

## fixture追加前の必須条件

第三者packageへ対象を広げる前に、少なくともRoute 53 Resolver DNS Firewallまたは管理下DNS proxy、artifact取得専用mirror、account-level budget/quota、concurrency admission、より強いdisk/pid/cgroup制限、incident cleanup runbookを追加してください。このMVPのdeny-egress SGだけを「完全なネットワーク遮断」と表現してはいけません。

ACKの操作権限にはPreview controllerとの互換性を優先して対象resource `*`を含めています。またEKS API endpointはpublic/private両方を有効にし、IAM認証に依存します。専用accountのデモに限定した判断であり、本番化ではACK IAMの実APIに基づくresource-level制約とEKS public access CIDR制限が必要です。
