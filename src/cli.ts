#!/usr/bin/env node
import { writeFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

import { audit } from "./audit.js";
import { toMarkdown, toSummary } from "./format.js";

type Format = "json" | "markdown" | "summary";

interface Args {
  dir?: string;
  format: Format;
  skip: string[];
  dangerousCaps?: string[];
  failOnHigh: boolean;
  out?: string;
  help: boolean;
}

const FORMATS: Format[] = ["json", "markdown", "summary"];

function parseArgs(argv: string[]): Args {
  const args: Args = { format: "json", skip: [], failOnHigh: false, help: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "-h" || a === "--help") args.help = true;
    else if (a === "--format") {
      const v = argv[++i] as Format;
      if (!FORMATS.includes(v)) throw new Error(`--format must be one of: ${FORMATS.join(", ")}`);
      args.format = v;
    } else if (a === "--skip") {
      const v = argv[++i];
      if (v) args.skip.push(...v.split(",").map((s) => s.trim()).filter(Boolean));
    } else if (a === "--dangerous-capabilities") {
      args.dangerousCaps = argv[++i].split(",").map((s) => s.trim()).filter(Boolean);
    } else if (a === "--fail-on-high") args.failOnHigh = true;
    else if (a === "--out") args.out = argv[++i];
    else if (!a.startsWith("-")) args.dir = a;
    else throw new Error(`Unknown option: ${a}`);
  }
  return args;
}

const HELP = `k8s-pod-security-audit — audit workload manifests against the Pod Security Standards

Usage:
  k8s-pod-security-audit <manifests-dir>
      [--format json|markdown|summary]
      [--skip path-substring,path-substring]
      [--dangerous-capabilities SYS_ADMIN,NET_ADMIN,…]
      [--fail-on-high]
      [--out FILE]

Walks the directory recursively, parses workload manifests (Pod / Deployment /
DaemonSet / StatefulSet / Job / CronJob), and reports findings:

  - privileged-container (high)
  - host-namespace (high)             hostNetwork / hostPID / hostIPC
  - host-path-mount (high)
  - privilege-escalation-allowed (high explicit / medium default)
  - added-dangerous-capability (high) SYS_ADMIN, NET_ADMIN, NET_RAW, …
  - run-as-root-allowed (medium)
  - missing-runAsNonRoot (medium)
  - missing-seccomp-profile (medium)
  - missing-resource-limits (medium)
  - default-service-account-with-automount (medium)
  - writable-root-fs (low)
  - missing-resource-requests / liveness-probe / readiness-probe (low)

Exit codes:
  0 — no high findings (or --fail-on-high not set)
  1 — high finding AND --fail-on-high set
  2 — usage / I/O error`;

export function run(argv: string[]): number {
  let args: Args;
  try {
    args = parseArgs(argv);
  } catch (e) {
    process.stderr.write(`${(e as Error).message}\n`);
    return 2;
  }
  if (args.help || !args.dir) {
    process.stdout.write(`${HELP}\n`);
    return args.help ? 0 : 2;
  }

  let report;
  try {
    const opts: { skip: string[]; dangerousCapabilities?: string[] } = { skip: args.skip };
    if (args.dangerousCaps) opts.dangerousCapabilities = args.dangerousCaps;
    report = audit(args.dir, opts);
  } catch (e) {
    process.stderr.write(`error scanning ${args.dir}: ${(e as Error).message}\n`);
    return 2;
  }

  let out: string;
  if (args.format === "json") out = JSON.stringify(report, null, 2);
  else if (args.format === "markdown") out = toMarkdown(report);
  else out = toSummary(report);

  if (args.out) writeFileSync(args.out, `${out}\n`, "utf8");
  else process.stdout.write(`${out}\n`);

  if (args.failOnHigh && !report.ok) return 1;
  return 0;
}

const invokedDirectly =
  process.argv[1] !== undefined &&
  import.meta.url === pathToFileURL(process.argv[1]).href;

if (invokedDirectly) {
  try {
    process.exit(run(process.argv.slice(2)));
  } catch (e) {
    process.stderr.write(`fatal: ${(e as Error).message}\n`);
    process.exit(2);
  }
}
