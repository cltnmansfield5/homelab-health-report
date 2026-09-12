# Architecture and boundaries

~~~mermaid
flowchart TD
  H["Ubuntu helper"] -->|"fixed, read-only exports"| C["Collector"]
  D["Docker Engine"] --> G["GET gateway"]
  G --> C
  C --> Q["Bundle queue"]
  Q --> U["Uploader"]
  U --> I["Drive Inbox"]
  I --> R["Report worker"]
  R --> F["Reports and receipts"]
  F -->|"cleanup eligibility"| U
~~~

The gateway and collector share an internal network. The uploader uses a separate
outbound network and shares only the bundle directory with the collector. No host
ports, privileged containers, host PID namespace or host-root mounts are used.

## Trusted components

The gateway is trusted because it holds the Docker socket. It accepts only GET
for ping/version, container list/inspect, bounded logs, one-shot stats and container
events. It rejects client bodies and forwards no client headers. Concurrency,
response size and time are bounded. Docker API 1.41+ is required and negotiated.

The API filter prevents ordinary callers from sending mutations; it does not
protect the daemon after gateway code execution. Permitted inspect/log endpoints
also expose sensitive Docker data to a compromised collector. Export field
selection and redaction reduce what is saved, not what that caller could read.

The helper has root-owned code/config, a protected filesystem and one writable
export directory. It runs fixed argv without a shell, with output/time limits.
It has no listening API, container-supplied command channel, Docker socket or
uploader credentials. Its journal and device capabilities remain powerful;
missing NVMe permissions are reported rather than adding CAP_SYS_ADMIN.

The uploader holds an OAuth credential that may cover more than the selected
folders. Folder IDs select destinations; Drive permissions control authorization.
Receipts are trusted input from the private Reports folder and authorize only
known bundle retention. They are not cryptographic proof of a completed review.

## Evidence contract

Spools record UTC collection times, plus original journal/Docker event times.
Counters need valid elapsed intervals and matching boot/container identities.
Snapshots and bounded event replay cannot establish full-window availability.
Removed containers or rotated logs can disappear before bundling.

The archive is created before its marker; the marker uploads only after archive
verification. Readers check SHA-256, member hashes, paths, types and expansion
limits, including tar metadata. Files are never executed or extracted to arbitrary
paths. See the [protocol](bundle-protocol.md) and [security notes](../SECURITY.md).
