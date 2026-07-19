# ADR 0001: npm offline fixtures, strace, deterministic policy

- Status: Accepted
- Date: 2026-07-19

## Context

初回記事でACK、Lambda MicroVM lifecycle、package behavior、network safety、cleanupを同時に見せる。pip、registry mirror、eBPF、LLMまで含めると、失敗原因とsecurity claimが曖昧になる。

## Decision

- npmだけを扱い、good/canary tarballをMicroVM imageへ事前格納する。
- Python runner、Go/controller-runtime Orchestrator、CDK TypeScriptを使う。
- dynamic observerはstraceとselected filesystem diffに限定する。
- riskはversioned deterministic ruleだけにし、LLM/Strandsを入れない。
- Kubernetes statusにはreport URI/hash/summaryだけを保存する。

## Consequences

再現性、安全性、記事の読みやすさは上がる。一方、任意package、transitive dependencies、registry behavior、完全なnetwork hostname観測は示せない。これらはcontrolled mirror/sinkを設計した第2段階へ送る。
