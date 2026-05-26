import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";

import { parseAllDocuments } from "yaml";

import {
  DEFAULT_DANGEROUS_CAPABILITIES,
  WORKLOAD_KINDS,
  type AuditOptions,
  type AuditReport,
  type Finding,
  type FindingCode,
  type FindingSeverity,
  type PodSpec,
  type WorkloadKind
} from "./types.js";

interface ManifestDoc {
  apiVersion?: string;
  kind?: string;
  metadata?: { name?: string; namespace?: string };
  spec?: unknown;
}

export function listManifestFiles(root: string, skip: string[] = []): string[] {
  const out: string[] = [];
  const visit = (dir: string): void => {
    for (const entry of readdirSync(dir)) {
      const full = join(dir, entry);
      const st = statSync(full);
      if (skip.some((s) => full.includes(s))) continue;
      if (st.isDirectory()) visit(full);
      else if (/\.ya?ml$/i.test(entry)) out.push(full);
    }
  };
  visit(root);
  return out.sort();
}

/** Resolve the PodSpec for any workload kind. Returns undefined for non-workload docs. */
export function podSpecOf(doc: ManifestDoc): PodSpec | undefined {
  if (!doc.kind || !WORKLOAD_KINDS.has(doc.kind as WorkloadKind)) return undefined;
  const spec = doc.spec as Record<string, unknown> | undefined;
  if (!spec) return undefined;
  if (doc.kind === "Pod") return spec as PodSpec;
  if (doc.kind === "CronJob") {
    const jt = (spec.jobTemplate as { spec?: { template?: { spec?: PodSpec } } } | undefined)?.spec;
    return jt?.template?.spec;
  }
  return (spec as { template?: { spec?: PodSpec } }).template?.spec;
}

function workloadFindings(
  doc: ManifestDoc,
  pod: PodSpec,
  source: string,
  dangerousCaps: ReadonlySet<string>
): Finding[] {
  const out: Finding[] = [];
  const kind = doc.kind as WorkloadKind;
  const name = doc.metadata?.name ?? "";
  const namespace = doc.metadata?.namespace;
  const base = (code: FindingCode, severity: FindingSeverity, message: string, container?: string): Finding => {
    const f: Finding = { code, severity, message, source, kind, name };
    if (namespace) f.namespace = namespace;
    if (container) f.container = container;
    return f;
  };

  // ─── pod-level findings ─────────────────────────────────────────────────
  if (pod.hostNetwork || pod.hostPID || pod.hostIPC) {
    out.push(
      base(
        "host-namespace",
        "high",
        `Pod uses host namespaces (hostNetwork=${!!pod.hostNetwork}, hostPID=${!!pod.hostPID}, hostIPC=${!!pod.hostIPC}).`
      )
    );
  }
  for (const vol of pod.volumes ?? []) {
    if (vol.hostPath) {
      out.push(base("host-path-mount", "high", `Volume "${vol.name}" mounts host path "${vol.hostPath.path}".`));
    }
  }
  if ((pod.serviceAccountName === undefined || pod.serviceAccountName === "default") && pod.automountServiceAccountToken !== false) {
    out.push(
      base(
        "default-service-account-with-automount",
        "medium",
        `Pod uses the default ServiceAccount with automountServiceAccountToken enabled.`
      )
    );
  }
  if (pod.securityContext?.runAsNonRoot !== true) {
    out.push(base("missing-runAsNonRoot", "medium", `Pod-level securityContext.runAsNonRoot is not set to true.`));
  }

  // ─── per-container findings ─────────────────────────────────────────────
  const containers = [...(pod.containers ?? []), ...(pod.initContainers ?? [])];
  for (const c of containers) {
    const ctx = { ...(pod.securityContext ?? {}), ...(c.securityContext ?? {}) };

    if (c.securityContext?.privileged === true) {
      out.push(base("privileged-container", "high", `Container is privileged.`, c.name));
    }
    if (c.securityContext?.allowPrivilegeEscalation === true) {
      out.push(base("privilege-escalation-allowed", "high", `Container sets allowPrivilegeEscalation: true.`, c.name));
    } else if (c.securityContext?.allowPrivilegeEscalation === undefined && !c.securityContext?.privileged) {
      out.push(
        base(
          "privilege-escalation-allowed",
          "medium",
          `Container does not pin allowPrivilegeEscalation: false (defaults to true).`,
          c.name
        )
      );
    }
    if (ctx.runAsNonRoot !== true && (c.securityContext?.runAsUser === undefined || c.securityContext.runAsUser === 0)) {
      out.push(base("run-as-root-allowed", "medium", `Container may run as root (runAsNonRoot != true, runAsUser != 0 pinned).`, c.name));
    }
    if (c.securityContext?.readOnlyRootFilesystem !== true) {
      out.push(base("writable-root-fs", "low", `Container does not pin readOnlyRootFilesystem: true.`, c.name));
    }
    for (const cap of c.securityContext?.capabilities?.add ?? []) {
      if (dangerousCaps.has(cap)) {
        out.push(base("added-dangerous-capability", "high", `Container adds dangerous capability "${cap}".`, c.name));
      }
    }
    if (!c.securityContext?.seccompProfile && !pod.securityContext?.seccompProfile) {
      out.push(base("missing-seccomp-profile", "medium", `No seccomp profile set on pod or container.`, c.name));
    }
    if (!c.resources?.limits) {
      out.push(base("missing-resource-limits", "medium", `Container has no resources.limits.`, c.name));
    }
    if (!c.resources?.requests) {
      out.push(base("missing-resource-requests", "low", `Container has no resources.requests.`, c.name));
    }
    if (!c.livenessProbe) {
      out.push(base("missing-liveness-probe", "low", `Container has no livenessProbe.`, c.name));
    }
    if (!c.readinessProbe) {
      out.push(base("missing-readiness-probe", "low", `Container has no readinessProbe.`, c.name));
    }
  }
  return out;
}

export function audit(root: string, opts: AuditOptions = {}): AuditReport {
  const generatedAt = opts.now ?? new Date().toISOString();
  const dangerousCaps = new Set(opts.dangerousCapabilities ?? DEFAULT_DANGEROUS_CAPABILITIES);
  const files = listManifestFiles(root, opts.skip);
  const findings: Finding[] = [];
  let documents = 0;
  let workloadsScanned = 0;
  let containersScanned = 0;

  for (const file of files) {
    const text = readFileSync(file, "utf8");
    const parsed = parseAllDocuments(text);
    parsed.forEach((d, idx) => {
      const json = d.toJSON() as ManifestDoc | null;
      if (!json || typeof json !== "object") return;
      documents += 1;
      if (!json.kind || !WORKLOAD_KINDS.has(json.kind as WorkloadKind)) return;
      const pod = podSpecOf(json);
      if (!pod) return;
      workloadsScanned += 1;
      containersScanned += (pod.containers?.length ?? 0) + (pod.initContainers?.length ?? 0);
      const source = parsed.length > 1 ? `${file}:${idx}` : file;
      findings.push(...workloadFindings(json, pod, source, dangerousCaps));
    });
  }

  return {
    generatedAt,
    files: files.length,
    documents,
    workloadsScanned,
    containersScanned,
    findings,
    ok: !findings.some((f) => f.severity === "high")
  };
}
