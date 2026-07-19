# Architecture

## 設計の中心

EKSは信頼できないパッケージを実行しません。Kubernetes API、ACK、状態機械、IAM、report storageをまとめるコントロールプレーンです。信頼できないnpm lifecycle codeは、検査ごとに復元したLambda MicroVMのguest kernel内だけで動かします。

```text
┌──────────────────────────── trusted EKS control plane ────────────────────────────┐
│                                                                                   │
│  PackageInspection CR                                                             │
│       │                                                                            │
│       ▼                                                                            │
│  package-inspection-controller                                                     │
│       ├── create/get/delete ──> ACK Microvm CR ──> Lambda MicroVM APIs             │
│       ├── CreateMicrovmAuthToken (8080 only, 5 min)                                │
│       ├── HTTPS POST /v1/scans; poll; download report                              │
│       ├── JSON Schema -> deterministic policy -> Markdown                          │
│       └── S3 PutObject -> delete child -> wait until child is absent               │
│                                                                                   │
│  IAM: ACK role and Orchestrator role are separate. Token is never written to CR.  │
└──────────────────────────────────────┬────────────────────────────────────────────┘
                                       │ public service endpoint + JWE
                                       ▼
┌──────────────────── untrusted Lambda MicroVM data plane ──────────────────────────┐
│  no execution role / no shell connector / deny-egress VPC connector               │
│                                                                                   │
│  root observer (trusted)                                                           │
│       ├── validate catalog digest                                                  │
│       ├── inspect tar without extracting                                           │
│       ├── snapshot selected filesystem roots                                       │
│       └── strace -ff -> sandbox wrapper -> setrlimit -> setuid(10001) -> npm       │
│                                                           └── lifecycle code       │
│  bounded JSON response                                                             │
└───────────────────────────────────────────────────────────────────────────────────┘
```

## 検査の状態遷移

```text
Pending
  -> Provisioning       ACK creates MicroVM
  -> Inspecting         RUNNING + endpoint + microvmID; submit deterministic scan ID
  -> Cleaning           report stored, or terminal failure recorded
  -> Succeeded|Failed   ACK child CR absent, therefore cleanup confirmed
```

任意の段階で`PackageInspection`が削除された場合、finalizerはACK childを削除し、そのchildが消えるまで残ります。ACK自身のfinalizerがAWS `TerminateMicrovm`完了を担当します。AWS側のeventual consistencyによりreconcileは冪等である必要があります。

## 検査処理

1. catalogから完全一致のpackage/versionを解決し、tarballのsizeとSHA-256を再計算する。
2. tarを展開せず、path traversal、symlink、special file、package metadata、lifecycle scripts、direct dependencies、license、静的patternを調べる。
3. package用project、home、npm cacheを一時workspaceへ作り、観測対象だけをsnapshotする。
4. root observerが`strace -ff`を開始し、その子のwrapperが各processのCPU time、core dump、open files、file sizeとUID全体のprocess countを制限してUID/GID 10001へdropする。guest全体のmemory baselineはMicroVM imageで1 GiBへ固定する。
5. `npm install --offline --foreground-scripts`を実行する。registryには接続しない。
6. filesystem差分、process/file/network syscall、canary self-report、resource usage、bounded stdout/stderrを正規化する。
7. EKS側でSchemaとrequested identityを再検証してからrisk ruleを適用する。

rootで動くのは観測supervisorだけです。信頼できないpackage codeを非rootにする一方、同じUIDの被観測processからobserverを分離し、UID drop後もsyscallを追跡するための選択です。

MicroVM imageの構築時だけは、digest固定したcontainer base imageとDebian packageを取得するためAWS管理の`INTERNET_EGRESS` connectorを使います。検査ごとの`RunMicrovm`には別のcustomer-managed deny-egress connectorを必須指定します。build planeとuntrusted runtime planeのnetwork policyを混同しません。

## Kubernetesを使う理由と使わない部分

Kubernetesの価値は宣言的API、reconciliation、owner reference/finalizer、RBAC、監査、ACKとの接続です。単発のパッケージ検査だけならLambda MicroVM SDKを直接呼ぶ小さなserviceの方が単純です。このデモは「Kubernetesをsandbox computeとしてではなくAWS sandbox fleetのcontrol planeとして使う」点を示すため、追加のEKS費用と複雑性を意図的に受け入れています。

EKS Job/Fargate/通常Lambdaと比べ、信頼できないcodeがEKS worker kernelを共有しないことがLambda MicroVM採用の主な理由です。ただし、Lambda MicroVMがなければ成立しない検査アルゴリズムではありません。gVisor/Kata/Firecracker on EC2でも類似の分離は可能です。
