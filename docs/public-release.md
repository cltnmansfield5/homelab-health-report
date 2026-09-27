# Release checks

## Source and licensing

Original code and documentation use [MIT](../LICENSE); preserve
[third-party notices](../THIRD_PARTY_NOTICES.md). Keep real diagnostics, rclone
credentials, local environment files and personal Drive identifiers outside Git.
Scan full reachable history as well as the working tree. The private predecessor
contains older deployment identifiers; a clean current example does not erase
that history. The public successor started from a separate reviewed snapshot.

## Validation

Run the [QA checks](validation.md), then require the exact proposed commit's CI
result. CI builds both targets, runs gateway/packaged-rclone integration tests,
scans history/current files, checks Python security rules and scans built images.
Use fresh vulnerability data at release time; prior CI does not clear later images.
The 2026-09-27 review added regressions for severity escalation and removal of
exec arguments from Docker event action strings in both code lines.

A successful offline run does not prove host mounts, Docker permissions, hardware
access, OAuth state or network controls. Check [Komodo adoption](komodo.md) and
verify a real newly produced drop using private data on the target host.

## Repository settings and publication

Require review and passing CI on the deployment branch, prevent force pushes,
limit webhook deployment to that branch, and enable private vulnerability reporting
and available secret/push-protection features. These settings need verification in
GitHub; a documentation commit cannot enforce them. Do not give untrusted pull
requests production credentials or privileged self-hosted CI runners.

Keep one deployment owner. Retain the outbox, uploader state and host settings
across upgrades. Do not rewrite deployed history or switch repository visibility
without an explicit reviewed publication step.
