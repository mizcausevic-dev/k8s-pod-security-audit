# k8s-pod-security-audit

Audit Kubernetes workload manifests against the [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/). Pure offline transform — no cluster access, no admission webhook to install.

Catches the cases that matter after the K8s 1.25 PodSecurityPolicy removal: privileged containers, host namespaces, hostPath mounts, dangerous capabilities, runAsRoot, missing seccomp profile, missing resource limits / probes, default ServiceAccount with token automount.

> Status: v0.1.0 — Node 20/22 supported, library + CLI. Lane #3 (Kubernetes control planes).

## What it flags

| Code | Severity | Rule |
|---|---|---|
| `privileged-container` | 🔴 | `securityContext.privileged: true` on a container. |
| `host-namespace` | 🔴 | `hostNetwork`, `hostPID`, or `hostIPC` set true. |
| `host-path-mount` | 🔴 | Volume mounts a path from the host. |
| `privilege-escalation-allowed` | 🔴 (explicit) / 🟠 (defaulted) | `allowPrivilegeEscalation: true`, or unset (defaults to true). |
| `added-dangerous-capability` | 🔴 | Container adds `SYS_ADMIN`, `NET_ADMIN`, `NET_RAW`, `SYS_PTRACE`, `SYS_MODULE`, `DAC_*`, `AUDIT_WRITE`. |
| `run-as-root-allowed` | 🟠 | `runAsNonRoot` not pinned true and `runAsUser` not pinned non-zero. |
| `missing-runAsNonRoot` | 🟠 | Pod-level `securityContext.runAsNonRoot` not set true. |
| `missing-seccomp-profile` | 🟠 | No seccomp profile on pod or container. |
| `missing-resource-limits` | 🟠 | Container has no `resources.limits`. |
| `default-service-account-with-automount` | 🟠 | Pod uses the `default` SA with `automountServiceAccountToken` enabled. |
| `writable-root-fs` | 🟡 | `readOnlyRootFilesystem` not pinned true. |
| `missing-resource-requests` | 🟡 | No `resources.requests`. |
| `missing-liveness-probe` / `missing-readiness-probe` | 🟡 | Container has no probe configured. |

## CLI

```
npx k8s-pod-security-audit <manifests-dir>
    [--format json|markdown|summary]
    [--skip path-substring,path-substring]
    [--dangerous-capabilities SYS_ADMIN,NET_ADMIN,…]
    [--fail-on-high]
    [--out FILE]
```

Walks the directory recursively, parses every `*.yaml` / `*.yml`, multi-doc files included. Supports the seven workload kinds: `Pod`, `Deployment`, `DaemonSet`, `StatefulSet`, `Job`, `CronJob`, `ReplicaSet`. CronJob → `jobTemplate.spec.template.spec` resolution is built in.

Exit codes:
- `0` — no high findings (or `--fail-on-high` not set)
- `1` — high finding AND `--fail-on-high` set
- `2` — usage / I/O error

Drop it into CI alongside [`k8s-deprecated-api-scanner`](https://github.com/mizcausevic-dev/k8s-deprecated-api-scanner) and [`k8s-rbac-overscope-finder`](https://github.com/mizcausevic-dev/k8s-rbac-overscope-finder) for a full pre-deploy pass.

## Library

```ts
import { audit, toMarkdown, DEFAULT_DANGEROUS_CAPABILITIES } from "k8s-pod-security-audit";

const report = audit("./manifests");
console.log(report.findings);   // [{ code, severity, kind, name, container, … }]
console.log(toMarkdown(report));
```

## Composes with

- [**`k8s-deprecated-api-scanner`**](https://github.com/mizcausevic-dev/k8s-deprecated-api-scanner) — scans for deprecated `apiVersion` usage.
- [**`k8s-rbac-overscope-finder`**](https://github.com/mizcausevic-dev/k8s-rbac-overscope-finder) — scans Role / ClusterRole / Binding for over-scope.
- [**`governance-disclosure-operator`**](https://github.com/mizcausevic-dev/governance-disclosure-operator), [**`scheduled-audit-operator`**](https://github.com/mizcausevic-dev/scheduled-audit-operator), [**`llm-cost-budget-operator`**](https://github.com/mizcausevic-dev/llm-cost-budget-operator) — operator surfaces; run this audit against their Helm `templates/`.

## Develop

```
npm install
npm run lint && npm run typecheck && npm run coverage && npm run build
npm run demo
```

## License

[AGPL-3.0-or-later](LICENSE)
