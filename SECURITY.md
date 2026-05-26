# Security Policy

`k8s-pod-security-audit` is a pure-transform library and CLI: it reads YAML files from a directory and emits a structured findings report. No cluster access, no network listener, no remote fetch, no execution of user-supplied code.

The input may include workload / container names and image references sensitive in your environment. The report includes those names; treat the input and report as you would your manifest repo.

## Supported versions

Only the latest tagged release is supported.

## Reporting a vulnerability

Please use GitHub Security Advisories for private disclosure:

- [Open a security advisory](https://github.com/mizcausevic-dev/k8s-pod-security-audit/security/advisories/new)

Do not file public issues for security reports.
