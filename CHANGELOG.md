# Changelog — harbor-registry-installer

## 2026-09-09 — Idempotence release (feature/idempotence-phase2)

Idempotence, certificate-lifecycle and uninstall-correctness pass. The installer now records
what it actually did, so maintenance commands operate on the real install instead of whatever
the current environment defaults to; the CA survives re-installs and renewals; and `uninstall`
no longer destroys a shared `/data`.

### Fixed
- **`REGISTRY_COMMON_NAME` default typo fixed** — `regsitry.edge.lab` → `registry.edge.lab`.
  Existing installs are handled through the recorded install state, so the change does not
  strand them.
- **CA reuse on re-install and renewal.** Certificate generation is split into CA generation
  and server-certificate generation: the CA pair is generated **only when none exists**, so
  re-running `install-harbor` or `update-certificates` issues a fresh server certificate
  signed by the existing CA and every client that already trusts the CA keeps working. An
  incomplete CA (only one of the two files present) is a hard error, not a silent
  regeneration.
- **`update-certificates` validates the new certificates BEFORE stopping the stack**, and
  verifies afterwards that the new certificate is actually being served.
- **The server private key is no longer copied into `/etc/docker/certs.d/`.** Only `ca.crt`
  and the client `.cert` are placed there; keys leaked there by older versions are swept on
  the next `update-certificates` or `uninstall-harbor`.
- **`uninstall-harbor` no longer removes `/data` wholesale by default.** Only the
  Harbor-created subpaths are removed (`ca_download`, `database`, `job_logs`, `redis`,
  `registry`, `secret`, `trivy-adapter`, `chart_storage`), so a shared `/data` mount survives.
  `PURGE_DATA=true` restores the old behavior.
- **Complete uninstall.** Removes the containers and `harbor-docker.service` (with
  `daemon-reload`/`reset-failed`), the `goharbor/*` images, `/opt/harbor`, `/var/log/harbor`,
  the install-files directory at its **recorded** path (works from any cwd), the
  `/etc/docker/certs.d/<FQDN>:<PORT>` entry for the recorded CN/port, and the docker group
  membership — only when the installer added it. Legacy installs with no `.install-env` get a
  fallback sweep that removes exactly those `certs.d` entries whose `ca.crt` byte-matches the
  installed Harbor CA.
- **Truthful exit codes** — any failed phase aborts non-zero. The systemd unit type is
  corrected, and secrets hygiene is applied throughout (`HARBOR_PASSWORD` masked in the
  fresh-install banner; `harbor.yml` root-only mode 600).
- **Existing-password handling is honest.** `HARBOR_PASSWORD` only applies on the very first
  install; on a re-install against an existing database the installer prints an explicit
  notice and the final banner reports that the existing password remains in effect rather
  than echoing the ignored new one. If project auto-creation then fails with HTTP 401, the
  install exits non-zero with the same explanation.
- **`/etc/docker/daemon.json` is merged, not clobbered** (via `jq`/`python3`), with a
  targeted revert on failure and a verified Docker startup — re-synced from the
  `images-pull-push` reference implementation.
- **EL10 kernel-modules guard before Docker start** — on RHEL/Rocky/Alma 10 the installer
  installs `kernel-modules-extra` matched to the running kernel (providing `xt_addrtype`)
  and exits with an explicit "reboot, then re-run" message rather than leaving a Docker that
  cannot start.
- **Distro handling** — RHEL uses Docker's `linux/rhel` repo, Rocky/Alma/CentOS the
  `linux/centos` path, SUSE the distro `docker` + `docker-compose` packages. Unsupported
  distributions exit with a clean error without touching any Docker configuration.
- **`MGMT_IP` / SAN IP override** for multi-homed hosts.

### Added
- **`/opt/harbor/.install-env`** (mode 600, root-only), written as the first mutating step of
  `install-harbor`. It records `REGISTRY_COMMON_NAME`, `HARBOR_PORT`, `HARBOR_VERSION`, the
  install date and user, the install-files directory, whether the installer added the docker
  group membership, and the CA fingerprint. **No passwords are stored in it.**
  `uninstall-harbor` and `update-certificates` consume it, resolving values as:
  explicit environment → `.install-env` → script default. `sudo bash install_harbor.sh
  update-certificates` with no variables now renews the certificates for the CN and port you
  actually installed with.
- **`PURGE_DATA`**, **`DOCKER_BRIDGE_CIDR`** and **`HARBOR_DB_PASSWORD`** documented as
  supported variables.
- **Preflight** for `curl` + `openssl` with the distro install hint.
- README sections for install-time state, CA reuse, uninstall scope, and the new variables.
- `install_harbor.sh` is now tracked executable (mode 755).

### Unchanged
- CLI surface (`install-harbor`, `uninstall-harbor`, `update-certificates`), the install
  layout (`/opt/harbor`, `/data`), and the Harbor version default are unchanged.
- Docker itself, `/etc/docker/daemon.json`, and the Docker repo configuration are
  intentionally **not** removed by `uninstall-harbor`.

### Known limitation
- Air-gap Trivy operation still uses Harbor's stock `skip_update: false` / `offline_scan:
  false` — the installer does not set them. Documented rather than silently claimed.
