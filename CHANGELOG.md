# Changelog — harbor-registry-installer

## v1.1.0 — 2026-11-03 — Day-2 fixes

### Added
- **`HARBOR_USERNAME` now works.** Any name other than `admin` used to do nothing: no such account was created, so a project
  step failed with a 401, and with no `PROJECTS` the install exited 0 with a name that couldn't log in. Harbor can't rename
  `admin`, so another name now becomes a second system administrator with the same password, and `admin` stays. It needs a
  password meeting Harbor's rule for new users. `HARBOR_USER_EMAIL` sets its email.
- **`ROTATE_CA=true`** replaces the CA, as `ca.crt.old-<stamp>`. A failed rotation puts the old one back. `CA_EXPIRY_WARN_DAYS` sets when a warning appears.
- **`HARBOR_FORCE_ONLINE=true`** ignores a `VERSION.txt` left behind by `offline-prep`.
- **`HARBOR_FORCE_REDEPLOY=true`**, `CERT_RENEW_BEFORE_DAYS` and `HARBOR_API_WAIT_SEC`.
- **`DOCKER_VERSION`, `INSTALL_PACKAGES_REF`, `INSTALL_PACKAGES_URL` and `INSTALL_PACKAGES_SHA256`.**
- **`version`, and `SCRIPT_VERSION`.** `.install-env` records `INSTALLER_VERSION`.
- **Tests:** `tests/unit`, `tests/contract` and `tests/integration`.

### Changed
- **An unchanged re-run now does nothing to the running stack.** No package changes, no new key, no Docker restart and
  no redeploy. It only checks the API and adds new projects. **The first re-run after this release still redeploys
  once,** because of how `harbor.yml` now quotes passwords.
- **A redeploy keeps the server key while it's still good,** and Docker restarts only when `daemon.json` changed on a
  Docker that was already running.
- **A re-run no longer moves Docker,** because `install_packages.sh` is now called with `--no-upgrade` once Docker is
  installed. `DOCKER_VERSION` applies only to a new install or a bundle, so change a running Docker by hand.
- `install_packages.sh` now defaults to tag `v1.1.0` rather than `main`. **Release install-packages v1.1.0 first,** or
  the default won't resolve. A cached copy from another ref is fetched again.

### Fixed
- **A failed upgrade no longer leaves `.install-env` naming a version that isn't running.** `HARBOR_VERSION` now changes
  only once the install succeeds. The installer is fetched first, so a bad version fails with nothing changed.
- **Uninstall removes a docker group membership it added,** even after a re-run. `DOCKER_GROUP_USERS` replaces the old
  flag, and older records are still read.
- **An expired CA stops the run** instead of issuing certificates no client accepts, and verification now checks the
  chain as well as the fingerprint. A server certificate can't outlive its CA.
- **A failed `update-certificates` restores the previous certificates and restarts Harbor** instead of leaving it down.
- **A custom database password survives a bare re-run.** It used to become `root123`, which broke Harbor. A different
  value is now refused.
- **An empty variable counts as not set,** so `HARBOR_PORT=` can't move an install to the defaults.
- **Special characters in passwords** no longer break `harbor.yml`, the API check or the read-back.
- **An upgrade now loads its images from the installer.** The old version's image archive was still in `/opt/harbor`, so
  upstream's `install.sh` skipped `docker load`. Connected, the images quietly came from Docker Hub. **Air-gapped, a new bundle
  over an older install failed,** and left the old version running.
- **A downgrade is refused before anything changes.** 2.15.0 to 2.14.1 left the API at 502 and the stack down, because an
  older Harbor can't start on a newer database. `HARBOR_ALLOW_DOWNGRADE=true` skips the check.
- **A stale nginx no longer fails the install with a misleading 401.** On a slow host Harbor's core can crash once on first
  boot, come back on a new address, and leave nginx sending API calls to another container. The installer now spots this
  and restarts nginx.
- **Air-gapped bundles include `curl`,** which the API check needs. A bundle and host with neither now fail at preflight
  rather than after a full install.
- README: `.cert` doesn't go in `certs.d`. The manual steps in Appendix A created the "missing key" failure.

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
