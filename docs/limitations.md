# Observability and limitations

## MVPで取得するもの

- package名、version、tarball size/SHA-256、integrity result
- package内file一覧、`package.json` metadata、license
- npm lifecycle scripts、direct dependencies
- source textに対する限定的な危険API/path pattern
- CycloneDX形式の最小SBOM
- selected rootsのinstall前後file差分
- `strace`の`execve`、fork/clone、open/openat、connect
- canaryが明示的に出すenvironment/DNS/HTTP attempt evidence
- wall time、user/system CPU、peak RSS、bounded stdout/stderr
- deterministic risk findingとMarkdown summary

## 取得しない、または不完全なもの

- 推移的依存: MVP fixtureには依存がなく、registry/networkも使わない
- 全filesystem: project、sandbox home、固定canary pathだけをsnapshotする
- 全environment read: libcの`getenv`はstraceで見えない。canary self-reportだけ
- DNS hostname: raw syscallは通常resolver IP/portしか示さない。hostnameはcanary self-reportだけ
- packet payload/PCAP/TLS SNI
- memory-only behavior、JIT後の意味、native binaryのsemantic analysis
- detached daemonがtimeout後に残す全挙動。process group killは行うがguest-wide証明ではない
- eBPF events。MVPは追加OS capabilityを要求しない
- vulnerability database/CVE lookup、provenance/SLSA verification
- license compatibility判断

static patternは文字列heuristicです。matchは悪意の証明ではなく、non-matchは安全の証明でもありません。canary self-reportは観測経路のデモには便利ですが、実在packageが協力してくれるわけではないため、strace evidenceと区別して`evidenceType`を記録します。

## networkに関する重要な注意

Lambda MicroVMはegress connectorを省略するとpublic Internet accessを持ちます。本実装は省略を許さず、outbound ruleなしSecurity Groupを付けたcustomer-managed VPC connectorへ固定します。

ただしVPCのAmazonProvidedDNS/Route 53 Resolverへの通信はSecurity Groupやnetwork ACLだけではfilterできません。そのためfixtureは予約済み`.test`だけを問い合わせ、CRDはfixture以外を拒否します。任意package対応にはDNS Firewallまたは管理下resolverが必要です。
