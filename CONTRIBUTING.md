# Contributing

Describe the problem, expected behavior, affected revision, and how the change was
verified. Use synthetic or redacted evidence. Do not attach local environment
files, database copies, OAuth credentials, diagnostic bundles, or real logs.
Read [SECURITY.md](SECURITY.md) before reporting a suspected vulnerability.

## Changes and deployment

1. Work on a branch and open a pull request against `main`.
2. Keep setup commands, environment examples, storage paths and operation notes
   consistent with the actual configuration. Explain migration and rollback steps.
3. Run the checks in [the release guide](docs/public-release.md) and inspect the
   CI result for the exact proposed commit.
4. Review volume identity, exposed ports, image versions, and required secrets
   before merging. A merge may trigger a Komodo webhook deployment.

Never run deployment or destructive cleanup as part of a documentation check.
A passing test suite cannot verify private host mounts or cloud permissions.
Do not grant pull requests from forks deployment credentials or a self-hosted
runner with production access. Avoid `pull_request_target` for untrusted code.

## Licensing

Original contributions use the [MIT license](LICENSE). Preserve the exceptions
and attributions in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
Do not copy an upstream implementation without its required notices.
