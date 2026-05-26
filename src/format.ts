import type { AuditReport, FindingSeverity } from "./types.js";

const SEVERITY_LABEL: Record<FindingSeverity, string> = {
  high: "🔴 high",
  medium: "🟠 medium",
  low: "🟡 low",
  info: "ℹ️  info"
};
const SEVERITY_RANK: Record<FindingSeverity, number> = { high: 0, medium: 1, low: 2, info: 3 };

export function toMarkdown(report: AuditReport): string {
  const lines: string[] = [];
  lines.push(report.ok ? `# K8s pod-security audit ✅` : `# K8s pod-security audit ❌`);
  lines.push(``);
  lines.push(`Generated: \`${report.generatedAt}\``);
  lines.push(``);
  lines.push(
    `- Files: ${report.files} · Documents: ${report.documents} · Workloads: ${report.workloadsScanned} · Containers: ${report.containersScanned}`
  );
  if (report.findings.length === 0) {
    lines.push(``);
    lines.push(`No pod-security findings.`);
    return lines.join("\n");
  }
  const ranked = [...report.findings].sort(
    (a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] || a.source.localeCompare(b.source)
  );
  lines.push(``);
  lines.push(`## Findings (${ranked.length})`);
  lines.push(``);
  lines.push(`| severity | code | kind | resource | container | message |`);
  lines.push(`|---|---|---|---|---|---|`);
  for (const f of ranked) {
    const resource = [f.namespace, f.name].filter(Boolean).join("/") || f.name;
    lines.push(
      `| ${SEVERITY_LABEL[f.severity]} | \`${f.code}\` | ${f.kind} | \`${resource}\` | ${f.container ?? "—"} | ${f.message} |`
    );
  }
  return lines.join("\n");
}

export function toSummary(report: AuditReport): string {
  const counts: Record<FindingSeverity, number> = { high: 0, medium: 0, low: 0, info: 0 };
  for (const f of report.findings) counts[f.severity] += 1;
  return `${report.workloadsScanned} workloads · ${report.containersScanned} containers · ${counts.high} high · ${counts.medium} medium · ${counts.low} low (${report.ok ? "ok" : "fail"})`;
}
