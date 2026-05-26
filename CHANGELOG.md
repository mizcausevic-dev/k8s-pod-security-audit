# Changelog

## v0.1.0 — 2026-05-27

- Initial release: audit Kubernetes workload manifests against the Pod Security Standards.
- 14 finding codes covering privileged containers, host namespaces (hostNetwork/hostPID/hostIPC), hostPath mounts, dangerous capabilities (SYS_ADMIN, NET_ADMIN, NET_RAW, SYS_PTRACE, SYS_MODULE, DAC_*, AUDIT_WRITE), runAsRoot, allowPrivilegeEscalation, missing seccomp profile, missing resource limits / requests / liveness / readiness probes, default ServiceAccount with token automount, writable root filesystem.
- Resolves PodSpec across Pod / Deployment / DaemonSet / StatefulSet / Job / CronJob / ReplicaSet (CronJob → jobTemplate.spec.template.spec).
- Library API: `audit(root, opts)` → `AuditReport`; `listManifestFiles`, `podSpecOf` helpers; `DEFAULT_DANGEROUS_CAPABILITIES`, `WORKLOAD_KINDS` exports.
- Formatters: `toMarkdown(report)` (severity-ranked) and `toSummary(report)`.
- CLI: `k8s-pod-security-audit <manifests-dir>` with `--format json|markdown|summary`, `--skip path,path`, `--dangerous-capabilities cap,cap`, `--fail-on-high`, `--out FILE`.
- Multi-document YAML aware (`---`). Uses `yaml` (eemeli/yaml) for structural parsing.
- Lane #3 (Kubernetes control planes) — third lane-#3 scanner alongside `k8s-deprecated-api-scanner` and `k8s-rbac-overscope-finder`.
- Node 20/22 CI (lint, typecheck, coverage, build, demo, `npm audit`), AGPL-3.0-or-later, Dependabot.
