# dev.to / Qiita demo outline

1. **Hook**: `postinstall`はどこまで見えるか。Podで実行せず、Kubernetesから使い捨てVMを払い出す。
2. **Scope disclaimer**: malware scannerではなく、2つの無害fixtureだけの技術デモ。
3. **Why npm first**: lifecycle hookが読者に分かりやすく、canaryとの差分を短い画面で示せる。
4. **Control plane vs data plane**: EKS/ACK/IAM/S3とLambda MicroVM guestを色分けした図。
5. **The trap**: egress connector省略時はpublic Internet access。deny connectorを必須にする。
6. **Live demo**: goodとcanaryの2 CRを同時にapplyし、`kubectl get packageinspections`をwatch。
7. **Evidence comparison**: lifecycle script 0/1、process 2/多、DNS 0/あり、network 0/あり、`/tmp`差分、AWS credential path。
8. **Cleanup proof**: `kubectl get microvms`が0、AWS CLIでもactive VMが0。
9. **Honest limitations**: DNS、strace blind spots、canary self-report、no arbitrary registry packages。
10. **Next iteration**: controlled mirror + DNS/HTTP sink。その後にpip、eBPF、Strandsによる説明を別記事へ分ける。

記事の中心メッセージは「Kubernetesで危険codeを実行する」のではなく、「KubernetesのreconciliationをAWS-managed VM sandboxのlifecycle controlに使う」です。
