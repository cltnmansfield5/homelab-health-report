# Security

The optional [Drive text transport](docs/text-transport.md) contains the same
private bytes as its source archive. Base64 does not encrypt or further redact
them. It uses the existing uploader credential and private Inbox, adds no host
listener or privilege, and retains full archive validation and receipt-gated
cleanup. Transport filenames and identities are checked before cleanup; no
arbitrary path from a transport index is extracted or executed.

This is a small diagnostic collector, not a security-certified agent. Publishing
source does not itself open a network path to a server; safe deployment still
depends on the host, Docker daemon, Portainer account and trusted build revision.

## Boundary

- No published container ports, privileged mode, host PID namespace or host-root
  mount. Containers run with a read-only root, dropped capabilities,
  no-new-privileges and resource/log limits.
- Only the gateway mounts the Docker socket. The mount's read-only flag does
  **not** restrict daemon operations. The code's GET allowlist rejects normal
  mutation attempts; gateway compromise can still compromise the Docker host.
  Never publish its port or attach unrelated applications to its network.
- The collector exports selected metadata and redacts common secrets. Permitted
  Docker inspect/log endpoints can still reveal sensitive data to a compromised
  collector. Free-form logs can evade redaction.
- The native helper runs trusted, root-owned code with fixed argv and bounded
  subprocesses. Its restricted capabilities still permit privileged journal/device
  access. It accepts no container-supplied commands and mounts no cloud credential.
  Unsupported NVMe reads remain gaps; do not add broad privileges as a shortcut.
- Only the uploader mounts OAuth credentials. Its Drive scope may extend beyond
  Inbox/Reports. Folder IDs are selectors, not access controls. Keep both folders,
  credentials, evidence and receipts private.

## Public-release hygiene

The current examples use generic host/remote values and empty Drive IDs. Put
personal deployment values in Portainer or an ignored local .env, and OAuth
tokens only in the protected host credential file. The Docker build context
allows only runtime Python files and the two generic config files.

This public repository starts from a reviewed snapshot without imported private
deployment history. Scan **history as well as the current tree** before releases.
Removing a value from a new commit does not remove it from old commits, tags,
pull requests or cached diffs. If an actual credential is committed, rotate it
and remove the exposure; deleting it from the latest source is insufficient.

Require review and passing CI for deployment changes; use a reviewed revision in
Portainer. Public pull requests must not gain repository write permissions or
host/cloud credentials. The CI workflow uses read-only repository permissions
and no deployment credentials.

## Checks and limits

CI scans Git history for secret patterns, checks Python security rules and scans
both built images for known vulnerabilities. These checks complement the gateway,
archive and retention tests; they cannot prove the absence of vulnerabilities.
Build dependencies and scanner databases change, so use a fresh CI result before
release and keep rebuilding reviewed security updates.
Python and Go images are pinned by digest; Alpine security packages refresh at
build time. Builds are therefore not byte-for-byte reproducible. The uploader
builds rclone v1.75.1 with the upstream gRPC fix for
[CVE-2026-84445](https://github.com/grpc/grpc-go/security/advisories/GHSA-2v4p-qf9q-27wj),
identified as `v1.75.1-homelab.1`. The compiler stays in the build stage.

Host firewall exposure, account security, the deployed image revision, Ubuntu
patches and actual device permissions require host-side verification. This repo
review does not remotely inspect or change them. Do not publish real diagnostic
bundles in issues, test fixtures or CI artifacts. Report suspected vulnerabilities
privately to the repository owner, without posting credentials or private logs.

[Docker daemon security](https://docs.docker.com/engine/security/) ·
[rclone Drive scope](https://rclone.org/drive/#scope) ·
[Architecture](docs/architecture.md)
