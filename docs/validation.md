# QA

Run from the checkout:

~~~bash
python3 -m unittest discover -v
python3 scripts/demo.py
bash -n scripts/prepare-host.sh
HH_UID=10001 HH_GID=10001 DOCKER_GID=999 docker compose config --quiet
~~~

GitHub Actions builds both images, checks generic config and environment
overrides, runs a real isolated Docker smoke test and tests the packaged rclone.
The smoke test creates and removes only its randomly named test resources.
It does not install the helper or contact Drive.

Security checks cover Python static analysis, tracked history/current-tree secret
scanning and image dependencies. The gateway tests reject mutations, body-bearing
GETs, arbitrary archive/exec routes and path/query bypasses. Archive tests cover
tampering, traversal, links, device entries and payload/metadata expansion.
Other regressions cover cookie redaction, property queries, failed samples,
subprocess descendants, upload ordering and receipt-gated retention.

Local environments without Docker/rclone or Unix sockets cannot run every
integration check. A passing synthetic test is not proof of host permissions,
Drive OAuth access, firewall settings or actual hardware health.
Use the exact commit's CI result and the deployment checks in
[Komodo setup](komodo.md) or optional [Portainer setup](portainer.md). See [security scope](../SECURITY.md).


## Added regression coverage

The current review checks that a warning-to-critical disk transition retains
critical severity and its supporting source even if input order changes, and
that Docker exec-create/start action suffixes cannot persist positional secrets.
Use `python3 -m unittest tests.test_regressions -v` for this focused coverage.
Report skipped integration tests explicitly; do not count a skipped rclone or
Docker test as executed. Run `bash -n scripts/prepare-host.sh scripts/security-check.sh`
before shell changes and inspect the full CI job for image/security checks.

## Optional export references

`python3 -m unittest tests.test_export_compaction tests.test_docker_export_compaction -v`
covers lossless v1/v2 roundtrips, source/member boundaries, dictionary resets,
recovery, redaction, legacy/new reporter parity, malformed references and bounded
expansion. Docker cases additionally preserve exact nanosecond pairs, IDs,
signed counters, future/literal shapes and failure output. Use
`scripts/benchmark-export-compaction.py` with a locally verified archive/marker
and `--docker-fields` to replay v2 retained evidence without committing private
data. See [rollout and limits](export-compaction.md); the
[fuller-report template](chatgpt-report-prompt.md) recognizes both versions.
