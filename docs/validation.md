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
[Portainer setup](portainer.md). See [security scope](../SECURITY.md).
