// Audit workload manifests against the Kubernetes Pod Security Standards.
// Reference: https://kubernetes.io/docs/concepts/security/pod-security-standards/

export type WorkloadKind = "Pod" | "Deployment" | "DaemonSet" | "StatefulSet" | "Job" | "CronJob" | "ReplicaSet";

export interface ContainerSecurityContext {
  privileged?: boolean;
  runAsUser?: number;
  runAsGroup?: number;
  runAsNonRoot?: boolean;
  allowPrivilegeEscalation?: boolean;
  readOnlyRootFilesystem?: boolean;
  capabilities?: { add?: string[]; drop?: string[] };
  seccompProfile?: { type?: string; localhostProfile?: string };
}

export interface ResourceRequirements {
  requests?: Record<string, string>;
  limits?: Record<string, string>;
}

export interface ContainerLike {
  name: string;
  image?: string;
  securityContext?: ContainerSecurityContext;
  resources?: ResourceRequirements;
  livenessProbe?: unknown;
  readinessProbe?: unknown;
  volumeMounts?: Array<{ name: string; mountPath?: string; readOnly?: boolean }>;
}

export interface PodSpec {
  hostNetwork?: boolean;
  hostPID?: boolean;
  hostIPC?: boolean;
  securityContext?: ContainerSecurityContext & { fsGroup?: number };
  containers?: ContainerLike[];
  initContainers?: ContainerLike[];
  volumes?: Array<{ name: string; hostPath?: { path: string; type?: string }; [key: string]: unknown }>;
  serviceAccountName?: string;
  automountServiceAccountToken?: boolean;
}

export type FindingSeverity = "high" | "medium" | "low" | "info";

export type FindingCode =
  | "privileged-container"
  | "host-namespace"
  | "host-path-mount"
  | "run-as-root-allowed"
  | "privilege-escalation-allowed"
  | "missing-resource-limits"
  | "missing-resource-requests"
  | "missing-liveness-probe"
  | "missing-readiness-probe"
  | "writable-root-fs"
  | "added-dangerous-capability"
  | "missing-seccomp-profile"
  | "default-service-account-with-automount"
  | "missing-runAsNonRoot";

export interface Finding {
  code: FindingCode;
  severity: FindingSeverity;
  message: string;
  source: string;
  kind: WorkloadKind;
  name: string;
  namespace?: string;
  container?: string;
}

export interface AuditReport {
  generatedAt: string;
  files: number;
  documents: number;
  workloadsScanned: number;
  containersScanned: number;
  findings: Finding[];
  ok: boolean;
}

export interface AuditOptions {
  now?: string;
  skip?: string[];
  /** Capabilities considered dangerous when added. */
  dangerousCapabilities?: string[];
}

export const DEFAULT_DANGEROUS_CAPABILITIES: string[] = [
  "SYS_ADMIN",
  "NET_ADMIN",
  "NET_RAW",
  "SYS_PTRACE",
  "SYS_MODULE",
  "DAC_READ_SEARCH",
  "DAC_OVERRIDE",
  "AUDIT_WRITE"
];

export const WORKLOAD_KINDS: ReadonlySet<WorkloadKind> = new Set([
  "Pod",
  "Deployment",
  "DaemonSet",
  "StatefulSet",
  "Job",
  "CronJob",
  "ReplicaSet"
]);
