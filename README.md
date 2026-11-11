# Harbor Registry Installer

A single-script installer for deploying [Harbor](https://goharbor.io/) container registry with Docker Compose, self-signed TLS certificates, and systemd service management. Supports online and air-gapped installations across multiple Linux distributions.

---

## Table of Contents

- [Quick Start](#quick-start)
- [Features](#features)
- [Supported Operating Systems](#supported-operating-systems)
- [Prerequisites](#prerequisites)
- [Usage](#usage)
- [Environment Variables](#environment-variables)
- [Examples](#examples)
- [Special Considerations](#special-considerations)
- [File Layout](#file-layout)
- [Appendix A: Manual Installation Steps](#appendix-a-manual-installation-steps)
- [Appendix B: Air-Gapped Installation](#appendix-b-air-gapped-installation)

---

## Quick Start

New here? This stands up a private Harbor container registry — Docker, a self-signed TLS certificate,
and a systemd service so it survives reboots — in a single command.

**Prerequisites**
- A Linux host with `root` / `sudo` (Ubuntu/Debian, RHEL/Rocky/AlmaLinux/CentOS, Fedora, or openSUSE Leap/SLES)
- ~4 GB RAM, 40 GB+ disk, and `curl` + `openssl` installed (the script preflight-checks these and prints
  the distro install hint if one is missing)
- Free TCP port **443** (override with `HARBOR_PORT`)
- A hostname for the registry — set it with `REGISTRY_COMMON_NAME` (default: `registry.edge.lab`;
  always pass your own for anything beyond a throwaway lab)

**1. Get the script**
```bash
git clone https://github.com/Chubtoad5/harbor-registry-installer.git
cd harbor-registry-installer
chmod +x install_harbor.sh
```

**2. Install, giving Harbor its hostname**
```bash
sudo REGISTRY_COMMON_NAME="registry.example.com" bash install_harbor.sh install-harbor
```

**3. Reach it**
- Open `https://registry.example.com` and log in as `admin` / `Harbor12345` — **change this on first
  login**.
- Make sure clients can resolve that hostname: add a DNS A record, or an `/etc/hosts` entry pointing it
  at the host's IP.
- Pushing/pulling from another machine? That client must trust the self-signed CA — see
  [Trusting the Self-Signed CA on Clients](#trusting-the-self-signed-ca-on-clients).

That's the happy path. For a custom port, pre-created projects, your own certificates, or an
air-gapped install, read on.

## Features

- Automated Docker CE installation (online or offline)
- Self-signed TLS certificate generation with SAN support (IP + DNS); the CA is generated once and reused across re-installs and renewals
- Harbor offline installer download, extraction, and configuration
- Systemd service creation for Harbor auto-start on boot
- Automatic Harbor project creation via the API
- Certificate update/rotation (self-signed or user-supplied) with post-update verification that the new certificate is actually being served
- Offline package generation for air-gapped deployments
- Clean uninstall driven by recorded install-time state (`/opt/harbor/.install-env`); `/data` removal is scoped by default
- Truthful exit codes: any failed phase aborts with a non-zero exit
- Debug mode for verbose output

## Supported Operating Systems

| Distribution | Notes |
|---|---|
| Ubuntu | Fully supported |
| Debian | Fully supported |
| RHEL | Docker's `linux/rhel` repo via `dnf` (`dnf-plugins-core` installed automatically if missing) |
| Rocky / AlmaLinux / CentOS | Docker's `linux/centos` repo via `dnf` (Docker's designated path for these) |
| Fedora | Docker repo via `dnf-3` |
| openSUSE Leap / SLES | Distro `docker` + `docker-compose` packages via `zypper` (no Docker CE repo exists for SUSE) |

Unsupported distributions exit with a clean error without touching any Docker configuration.

## Prerequisites

- Linux host with root or sudo access
- Internet access (for online installs)
- `curl` and `openssl` installed
- Minimum 4 GB RAM and 40 GB disk recommended for Harbor

## Usage

```
sudo bash install_harbor.sh <command>
```

### Commands

| Command | Description |
|---|---|
| `help` | Display usage information |
| `install-harbor` | Install Harbor registry (Docker, certs, Harbor, systemd service) |
| `uninstall-harbor` | Remove Harbor containers, data, service, and certificates |
| `offline-prep` | Generate a portable archive for air-gapped installation |
| `update-certificates` | Replace TLS certificates (generate new self-signed or supply your own) |

## Environment Variables

All variables have defaults and can be overridden by exporting them before running the script or passing them inline.

### Harbor Configuration

| Variable | Default | Description |
|---|---|---|
| `DEBUG` | `1` | Enable verbose debug output (`1` = on, `0` = off) |
| `HARBOR_VERSION` | `2.15.0` | Harbor release version to install |
| `HARBOR_PORT` | `443` | HTTPS port for the registry |
| `HARBOR_USERNAME` | `admin` | System administrator account. Harbor can't rename `admin`, so another name creates a second administrator with the same password, and `admin` stays. It needs 8 to 128 characters with a lowercase letter, an uppercase letter and a number. |
| `HARBOR_USER_EMAIL` | `<HARBOR_USERNAME>@<REGISTRY_COMMON_NAME>` | Email for that account |
| `HARBOR_PASSWORD` | `Harbor12345` | Admin password (change after first login). **Only applied on the very first install** — see [Changing the Admin Password](#changing-the-admin-password). Some characters are refused: see [Passwords](#passwords) |
| `HARBOR_DB_PASSWORD` | `root123` | Harbor's internal PostgreSQL password. Known limitation: the default is the Harbor-upstream `root123`; override it for production use. Written into `harbor.yml` (root-only, mode 600). See [Passwords](#passwords) |
| `DOCKER_BRIDGE_CIDR` | `172.30.0.1/16` | Docker bridge CIDR (`bip`). Merged into an existing `/etc/docker/daemon.json` (via `jq`/`python3`) — never clobbers other settings; skipped if `bip` is already defined |
| `PROJECTS` | _(empty)_ | Space-separated list of Harbor projects to create |
| `HARBOR_API_WAIT_SEC` | `60` | How long to wait for the Harbor API after (re)starting it |
| `LICENSE_OFFER_CONTACT` | the Chubtoad5 project | Who the air-gap bundle's written offer tells people to ask for source code |
| `HARBOR_FORCE_REDEPLOY` | `false` | `true` runs the full install even when nothing has changed |
| `HARBOR_FORCE_ONLINE` | `false` | `true` ignores a `VERSION.txt` left by `offline-prep`, and stays online |
| `HARBOR_DB_DUMP` | `true` | Before a version change, dump Harbor's database to `/data/backup/harbor-installer/`. `false` skips the dump. See [Upgrading Harbor](#upgrading-harbor) |
| `HARBOR_REMOVE_OLD_IMAGES` | `true` | After a successful version change, remove the `goharbor/*` images of other versions that no container uses. `false` keeps them |
| `HARBOR_ALLOW_DOWNGRADE` | `false` | `true` skips the check that refuses an older `HARBOR_VERSION` than the one installed. An older Harbor can't start on a newer database, so this is rarely what you want. |
| `DOCKER_VERSION` | _(empty)_ | Docker version for a new install, or for an `offline-prep` bundle. The start of a version is enough. A Docker that's already installed is never moved. |
| `INSTALL_PACKAGES_REF` | `v1.1.3` | Tag, branch or commit of `install_packages.sh` to fetch. `INSTALL_PACKAGES_URL` wins over it, and `INSTALL_PACKAGES_SHA256` checks it. |
| `MGMT_IP` | _(first `hostname -I` token)_ | Host IP used in the certificate SAN and printed URLs. Set explicitly on multi-homed hosts |
| `PURGE_DATA` | `false` | `uninstall-harbor` only: `true` removes `/data` entirely. Default removes only the Harbor-created subpaths — safe on shared `/data` mounts |

### Certificate Configuration

| Variable | Default | Description |
|---|---|---|
| `COUNTRY` | `US` | Certificate country code |
| `STATE` | `MA` | Certificate state |
| `LOCATION` | `BOSTON` | Certificate locality |
| `ORGANIZATION` | `SELF` | Certificate organization |
| `REGISTRY_COMMON_NAME` | `registry.edge.lab` | FQDN for the registry certificate (the historical `regsitry.edge.lab` typo default is fixed; existing installs are handled via the recorded install state, see below) |
| `DURATION_DAYS` | `730` | Server certificate validity in days, at most 730: a larger value is lowered to 730 with a warning, because Apple devices reject a server certificate valid for more than 825 days (see [CA Reuse](#ca-reuse-on-re-install-and-certificate-renewal)). It's never issued for longer than the CA has left |
| `CA_DURATION_DAYS` | `3650` | Lifetime of a CA the installer makes: on a first install, or with `ROTATE_CA=true`. An existing CA keeps its own. A CA being made can't be shorter than `DURATION_DAYS`. By default a 730-day certificate under a ten-year CA |

### Certificate Update Options

| Variable | Default | Description |
|---|---|---|
| `NEW_CERT_GEN` | `0` | Set to `1` to generate a new self-signed certificate |
| `USER_CERT_CRT` | _(empty)_ | Path to a user-supplied server certificate (.crt) |
| `USER_CERT_KEY` | _(empty)_ | Path to a user-supplied private key (.key) |
| `USER_CA_CRT` | _(empty)_ | Path to a user-supplied CA certificate (.crt) |

## Examples

### Basic Installation

```bash
sudo bash install_harbor.sh install-harbor
```

### Custom FQDN and Port

```bash
sudo REGISTRY_COMMON_NAME="registry.example.com" HARBOR_PORT=8443 bash install_harbor.sh install-harbor
```

### Install with Projects

```bash
sudo PROJECTS="dev staging production" bash install_harbor.sh install-harbor
```

### Custom Certificate Fields

```bash
sudo COUNTRY="DE" STATE="Bavaria" LOCATION="Munich" ORGANIZATION="MyOrg" \
  REGISTRY_COMMON_NAME="harbor.myorg.io" DURATION_DAYS=365 \
  bash install_harbor.sh install-harbor
```

### Regenerate Self-Signed Certificates

```bash
sudo NEW_CERT_GEN=1 bash install_harbor.sh update-certificates
```

### Update with User-Supplied Certificates

```bash
sudo USER_CERT_CRT=/path/to/server.crt \
     USER_CERT_KEY=/path/to/server.key \
     USER_CA_CRT=/path/to/ca.crt \
     bash install_harbor.sh update-certificates
```

### Uninstall

```bash
sudo bash install_harbor.sh uninstall-harbor
```

Removes only the Harbor-created subpaths of `/data` by default. To remove `/data` entirely:

```bash
sudo PURGE_DATA=true bash install_harbor.sh uninstall-harbor
```

### Prepare Offline Package

```bash
sudo bash install_harbor.sh offline-prep
```

## Special Considerations

### Install-Time State (`/opt/harbor/.install-env`)

The very first mutating step of `install-harbor` writes `/opt/harbor/.install-env` (mode 600, root-only).
It records the values the install actually used — `REGISTRY_COMMON_NAME`, `HARBOR_PORT`,
`HARBOR_VERSION`, the install date and user, the install-files directory, whether the installer added
the docker group membership, and the CA certificate fingerprint. **No passwords are ever stored in it.**

`uninstall-harbor` and `update-certificates` consume this file, so they operate on what was actually
installed instead of whatever the current environment defaults to. Precedence when resolving a value:

1. Variable explicitly set in the environment for this run
2. Value recorded in `/opt/harbor/.install-env`
3. Script default

This means `sudo bash install_harbor.sh update-certificates` (with no variables) renews certificates for
the CN and port you installed with — you no longer have to re-pass `REGISTRY_COMMON_NAME` on every
maintenance command.

### CA Reuse on Re-Install and Certificate Renewal

Certificate generation is split into CA generation and server-certificate generation. The CA pair
(`ca.crt`/`ca.key`) is generated **only when none exists** in `/opt/harbor/certs/`. Re-running
`install-harbor` or `update-certificates` (`NEW_CERT_GEN=1`) issues a fresh server certificate signed by
the **existing** CA, so every remote client that already trusts the CA keeps working. To deliberately
rotate the CA, remove `/opt/harbor/certs/ca.crt` and `ca.key` first (all clients must then re-trust the
new CA). An incomplete CA (only one of the two files present) is a hard error, not a silent regeneration.

Only `ca.crt` is placed in `/etc/docker/certs.d/<FQDN>:<PORT>/`. The server private key doesn't belong
there, and a `.cert` without its key makes every `docker login` fail with "missing key". Either one left
by an older version is cleaned up on the next `install-harbor` or `update-certificates`.

The CA's lifetime is `CA_DURATION_DAYS` (default 3650, ten years), and the server certificate's is `DURATION_DAYS`
(default 730). A short server certificate under a long CA means a renewal keeps the CA, so clients keep trusting it.
Changing `CA_DURATION_DAYS` later doesn't touch an existing CA: it applies the next time one is made.

**Server certificates are capped at 730 days** (since v1.3.0). Apple devices reject a TLS server certificate valid for
more than 825 days, even under a private CA, so Harbor's web UI fails in Safari and on iOS and macOS. Docker,
containerd, Podman and Helm don't check, so pulls and pushes would still work. A larger `DURATION_DAYS` is lowered to
730 with a warning. Before v1.3.0 the default was 3650 for both. A re-run keeps an existing certificate, however long.
Keep `CERT_RENEW_BEFORE_DAYS` (default 30) well under 730: a certificate
always inside its renewal window would be replaced, and Harbor redeployed, on every run. To replace a long one now,
under the same CA so clients keep trusting it:

```bash
sudo NEW_CERT_GEN=1 ./install_harbor.sh update-certificates
```

An expired CA stops `install-harbor` and `update-certificates` (with `NEW_CERT_GEN=1`) before anything
changes. `ROTATE_CA=true` replaces it, and every client must then trust the new one. A warning appears
when the CA has fewer than `CA_EXPIRY_WARN_DAYS` left (default 30). A server certificate is never issued
for longer than the CA has left.

### Re-running the installer

A re-run with nothing changed does nothing to the running stack: no package changes, no new key, no
Docker restart and no redeploy. It only checks the API and adds any new projects. A changed version, port,
name or anything else that lands in `harbor.yml` takes the full path, and so does a stack with a container
down, so a re-run can still repair a broken install. `HARBOR_FORCE_REDEPLOY=true` forces the full path.

The server key survives a redeploy while it's still good: valid against the CA, more than
`CERT_RENEW_BEFORE_DAYS` left (default 30), and right for the name, address and subject.

`HARBOR_PASSWORD` and `HARBOR_DB_PASSWORD` apply on a first install only. A re-run keeps the values in
`harbor.yml`. A different `HARBOR_DB_PASSWORD` is refused, because the database keeps the one it was
created with.

### Passwords

`harbor.yml` gets each password exactly, whatever it contains. But Harbor's `prepare` also writes them into env
files under `/opt/harbor/common/config/`, which docker compose reads with its own rules. Compose expands `$name`,
cuts a value at a `#` after a space, trims spaces at either end, and reads a leading quote as quoting. So an admin
password with any of these would give `admin` a different password, and the install would fail with a 401.

`HARBOR_PASSWORD` is refused before anything changes when it has:
- a `$` before a letter, `_`, `{` or another `$` (`$1`, `$-` and a trailing `$` are fine);
- a `#` after a space (`a#b` is fine);
- a space at the start or the end;
- a `"` or `'` at the start.

Control characters were refused already. `HARBOR_DB_PASSWORD` with any of these only gets a warning: every
container that uses it reads the same file, so Harbor works, but Postgres gets a shorter password than the one
passed.

An install made with such an admin password before v1.2.0 has the password compose produced. Log in with that,
then change it in the UI. For example, `Abc$xyz9Q #1` became `Abc`.

### Upgrading Harbor

An upgrade is a re-run with a newer `HARBOR_VERSION`. Harbor migrates its database when it starts, and an older
Harbor can't start on a migrated database, so a downgrade is refused. Two things happen around a version change:

- **Before it, a database dump.** `pg_dumpall` from `harbor-db`, compressed, to
  `/data/backup/harbor-installer/harbor-db-v<old version>-<UTC time>.sql.gz` (the folder is 700, the file 600).
  It comes after the new version's download, so a version that doesn't exist fails first, and before anything
  changes. A failed or empty dump stops the run. If Harbor is down, the installed version's database is started
  alone for it. The dump is small: Harbor's database is tens of MB. An install never removes dumps, and
  `uninstall-harbor` removes them with the rest of Harbor's data. `HARBOR_DB_DUMP=false` skips it.
- **After it succeeds, the old images go.** Every `goharbor/*` image not tagged for the running version, and
  not used by a container, is removed: a 2.14.1 set frees about 3.8 GB. A failed upgrade removes nothing. The old
  version's offline installer stays in `harbor-install-files/`, because a rollback needs it: delete it once the
  upgrade is trusted. `HARBOR_REMOVE_OLD_IMAGES=false` keeps the images.

### Restoring the database after a failed upgrade

A failed upgrade can leave Harbor down, on a database the new version has already migrated. To go back to the
old version with the dump made before the upgrade (tested from 2.15.0 back to 2.14.1):

```bash
# 1. Stop Harbor, and set the migrated database aside
sudo systemctl stop harbor-docker
sudo cp -p /opt/harbor/harbor.yml /root/harbor.yml.before-restore     # the passwords step 2 needs
sudo mv /data/database /data/database.failed-$(date -u +%Y%m%d%H%M%S)

# 2. Reinstall the old version on an empty database, with the settings it had. Both passwords must be the ones in
#    /opt/harbor/harbor.yml (harbor_admin_password, and database: password:), so harbor.yml keeps them: the dump
#    restores the database's own, and a later re-run reads harbor.yml's
sudo HARBOR_VERSION=<old version> HARBOR_PASSWORD='<as before>' HARBOR_DB_PASSWORD='<as before>' \
  REGISTRY_COMMON_NAME=<as before> ./install_harbor.sh install-harbor

# 3. Load the dump into the database alone
sudo systemctl stop harbor-docker
sudo docker compose -f /opt/harbor/docker-compose.yml up -d postgresql
sudo docker exec harbor-db pg_isready -U postgres     # repeat until it says "accepting connections"
sudo sh -c 'gzip -dc /data/backup/harbor-installer/harbor-db-v<old version>-<time>.sql.gz \
  | docker exec -i harbor-db psql -U postgres -d postgres -q'

# 4. Start Harbor
sudo systemctl start harbor-docker
```

- **Step 2** must pass the same `HARBOR_USERNAME`, `HARBOR_PORT` and other settings the install had, if they weren't
  the defaults. It needs the old version's offline installer in `harbor-install-files/`. The upgrade keeps it. Online, it's
  downloaded again if it's gone. Air-gapped, keep the old bundle until the upgrade is trusted.
- **Step 3** prints two errors, which are expected: `current user cannot be dropped` and `role "postgres" already
  exists`. Users, projects, robot accounts and image records come back as they were before the upgrade.
- **Images** pushed after the upgrade keep their files in `/data/registry`, but the restored database doesn't list
  them: push them again.
- **Passwords copied from `harbor.yml`:** it writes `"` as `\"` and `\` as `\\` inside the quotes. Undo those when
  passing them in step 2.
- **Afterwards,** a re-run with the old version says "No change". Delete `/root/harbor.yml.before-restore`, which holds
  both passwords, and `/data/database.failed-*` once the restore is trusted: `uninstall-harbor` removes neither.
- **These steps are for the installer's own dumps,** made with `pg_dumpall --clean --if-exists`, so they load over
  the fresh database step 2 makes.

### Running Behind a Proxy

The generated `harbor.yml` includes a `proxy` section. If your environment requires an HTTP/HTTPS proxy, edit `/opt/harbor/harbor.yml` after installation and set `http_proxy`, `https_proxy`, and `no_proxy` under the `proxy:` block, then restart Harbor:

```bash
docker compose -f /opt/harbor/docker-compose.yml down
docker compose -f /opt/harbor/docker-compose.yml up -d
```

### DNS Resolution

Clients pulling images must be able to resolve `REGISTRY_COMMON_NAME`. If DNS is not available, add an entry to `/etc/hosts` on each client:

```
192.168.1.100  registry.edge.lab
```

### Trusting the Self-Signed CA on Clients

Docker clients that push/pull images from this registry need the CA certificate. After installation, the CA is available for download at `/data/ca_download/ca.crt` on the Harbor host.  

Alternatively, you can download the CA certificate from the Harbor web UI from Prjects > **your project** > REGISTRY CERTIFICATE link.  

Download using curl
```
curl -k https://<REGISTRY_COMMON_NAME>:<PORT>/api/v2.0/systeminfo/getcert -o ca.crt
```

On each Docker client:

```bash
# Copy the CA to the client
sudo mkdir -p /etc/docker/certs.d/<REGISTRY_COMMON_NAME>:<PORT>
sudo cp ca.crt /etc/docker/certs.d/<REGISTRY_COMMON_NAME>:<PORT>/
sudo systemctl restart docker
```

### Data Persistence

Harbor stores all registry data under `/data` and configuration under `/opt/harbor`. Back up these directories before any upgrade or uninstall operation. A version change dumps the database first (see [Upgrading Harbor](#upgrading-harbor)), but images and other files aren't in that dump.

### Changing the Admin Password

The `HARBOR_PASSWORD` variable only sets the initial password during first installation. Change it through the Harbor web UI after deployment. Subsequent reinstalls will not update an existing password stored in the Harbor database under `/data` — the installer detects this, prints an explicit notice, and the final banner reports that the existing password remains in effect rather than echoing the ignored new one. If project auto-creation then fails with HTTP 401, the install exits non-zero with the same explanation.

### Uninstall Scope

`uninstall-harbor` removes: the Harbor containers and `harbor-docker.service` (including a
`daemon-reload`/`reset-failed`), the `goharbor/*` images, `/opt/harbor` (config, certs, `.install-env`),
`/var/log/harbor`, the install-files directory at its **recorded** path (works from any cwd), the
`/etc/docker/certs.d/<FQDN>:<PORT>` entry for the recorded CN/port, and the docker group membership —
only when the installer added it. For installs made before `.install-env` existed, a fallback sweep
removes exactly those `/etc/docker/certs.d/*` entries whose `ca.crt` byte-matches the installed Harbor CA.

`/data` handling: by default only the Harbor-created subpaths are removed (`ca_download`, `database`,
`job_logs`, `redis`, `registry`, `secret`, `trivy-adapter`, `chart_storage`, and the database dumps in
`backup/harbor-installer`) so a shared `/data` mount is never destroyed. `/data/backup` itself goes only when
nothing else is left in it. Set `PURGE_DATA=true` to remove `/data` entirely.

Docker itself, `/etc/docker/daemon.json`, and the Docker repo configuration are intentionally **not**
removed.

### Systemd Service

The installer creates `harbor-docker.service` so Harbor starts automatically on boot. Manage it with standard systemctl commands:

```bash
sudo systemctl status harbor-docker.service
sudo systemctl restart harbor-docker.service
sudo systemctl stop harbor-docker.service
```

### Certificate Update Behavior

The `update-certificates` command stops Harbor, replaces certificates, regenerates `harbor.yml` (using the recorded install-time CN/port and preserving the running install's admin/DB passwords unless explicitly re-passed), runs Harbor's `prepare` so nginx actually picks up the new certificate, and restarts the stack via `harbor-docker.service`. This causes a brief outage. It then **verifies** with `openssl s_client` that the certificate being served matches the one on disk (SHA256 fingerprint) and exits non-zero if it does not — success output means the new certificate is genuinely live.

The command requires either `NEW_CERT_GEN=1` or all three `USER_CERT_*` / `USER_CA_CRT` variables to be set; otherwise it exits with an error. With `NEW_CERT_GEN=1` the existing CA is reused (see [CA Reuse](#ca-reuse-on-re-install-and-certificate-renewal)). User-supplied certificates must chain to the provided CA and are validated with `openssl verify` before installation.

## File Layout

After installation, the script creates the following structure:

```
<working-directory>/
  harbor-install-files/
    apt-packages/             # install_packages.sh helper
    harbor-offline-installer-v<VERSION>.tgz
    read_this_crumb.txt       # Post-install summary (mode 600, contains no credentials)

/opt/harbor/                  # Harbor application
  .install-env                # Recorded install-time state (mode 600, no secrets)
  harbor.yml                  # Harbor configuration (mode 600 - carries passwords)
  docker-compose.yml          # Docker Compose file (from installer)
  certs/                      # Generated or user-supplied certificates
    ca.crt, ca.key
    <FQDN>.crt, <FQDN>.cert, <FQDN>.key, <FQDN>-fullchain.crt

/data/                        # Harbor persistent data
  ca_download/ca.crt          # CA cert available for client download

/etc/docker/certs.d/<FQDN>:<PORT>/   # Docker client trust store (ca.crt only)
/etc/systemd/system/harbor-docker.service
```

---

## Appendix A: Manual Installation Steps

If you prefer to install Harbor without the script, follow these steps. All commands assume root or sudo access.

### Step 1: Install Docker

Install Docker CE and its dependencies. Refer to the [official Docker documentation](https://docs.docker.com/engine/install/) for your distribution. For Ubuntu:

```bash
# Add Docker GPG key and repository
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc

echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] \
  https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}") stable" \
  | tee /etc/apt/sources.list.d/docker.list > /dev/null

apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

systemctl enable --now docker
usermod -aG docker $USER
```

### Step 2: Generate TLS Certificates

Replace `<FQDN>` with your registry hostname (e.g., `registry.example.com`) and `<IP>` with the host's IP address.

```bash
FQDN="registry.example.com"
CA_DAYS=3650     # the CA: ten years
DAYS=730         # the server certificate: at most 825, or Apple devices reject it
CERT_DIR="./certs"
mkdir -p $CERT_DIR

# Generate CA
openssl genrsa -out $CERT_DIR/ca.key 4096
openssl req -x509 -new -nodes -sha512 -days $CA_DAYS \
  -subj "/C=US/ST=MA/L=Boston/O=MyOrg/CN=$FQDN" \
  -key $CERT_DIR/ca.key -out $CERT_DIR/ca.crt

# Generate server key and CSR
openssl genrsa -out $CERT_DIR/$FQDN.key 4096
openssl req -sha512 -new \
  -subj "/C=US/ST=MA/L=Boston/O=MyOrg/CN=$FQDN" \
  -key $CERT_DIR/$FQDN.key -out $CERT_DIR/$FQDN.csr

# Create SAN extension file
cat > $CERT_DIR/v3.ext <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
IP.1=<IP>
DNS.1=$FQDN
DNS.2=$(hostname)
EOF

# Sign the certificate
openssl x509 -req -sha512 -days $DAYS \
  -extfile $CERT_DIR/v3.ext \
  -CA $CERT_DIR/ca.crt -CAkey $CERT_DIR/ca.key -CAcreateserial \
  -in $CERT_DIR/$FQDN.csr -out $CERT_DIR/$FQDN.crt

```

### Step 3: Install Certificates for Docker

```bash
FQDN="registry.example.com"
PORT=443

# Only client trust material belongs in certs.d - never the private key
mkdir -p /etc/docker/certs.d/$FQDN:$PORT
cp $CERT_DIR/ca.crt     /etc/docker/certs.d/$FQDN:$PORT/

# Make CA available for client download
mkdir -p /data/ca_download
cp $CERT_DIR/ca.crt /data/ca_download/ca.crt

systemctl restart docker
```

### Step 4: Download and Extract Harbor

```bash
HARBOR_VERSION="2.15.0"
curl -fsSLO https://github.com/goharbor/harbor/releases/download/v${HARBOR_VERSION}/harbor-offline-installer-v${HARBOR_VERSION}.tgz
tar xzvf harbor-offline-installer-v${HARBOR_VERSION}.tgz -C /opt/
```

### Step 5: Configure harbor.yml

Edit `/opt/harbor/harbor.yml` with your settings. The critical fields are:

```yaml
hostname: registry.example.com

https:
  port: 443
  certificate: /path/to/certs/registry.example.com.crt
  private_key: /path/to/certs/registry.example.com.key

harbor_admin_password: "YourSecurePassword"

data_volume: /data
```

### Step 6: Run the Harbor Installer

```bash
/opt/harbor/install.sh
```

### Step 7: Create a Systemd Service (Optional)

```bash
cat > /etc/systemd/system/harbor-docker.service <<EOF
[Unit]
Description=Harbor
After=docker.service systemd-networkd.service systemd-resolved.service
Requires=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/docker compose -f /opt/harbor/docker-compose.yml up -d
ExecStop=/usr/bin/docker compose -f /opt/harbor/docker-compose.yml down

[Install]
WantedBy=multi-user.target
EOF

chmod 644 /etc/systemd/system/harbor-docker.service
systemctl daemon-reload
systemctl enable --now harbor-docker.service
```

### Step 8: Verify

Open `https://<FQDN>` in a browser and log in with the admin credentials.

---

## Appendix B: Air-Gapped Installation

Use this workflow when the target host has no internet access.

### Preparation (on a connected host)

The connected host must be running the **same OS and version** as the target.

1. Clone this repository on the connected host:

   ```bash
   git clone <repo-url>
   cd harbor-registry-installer
   ```

2. Run the offline preparation command:

   ```bash
   sudo bash install_harbor.sh offline-prep
   ```

   This will:
   - Download Docker CE packages for your OS. On Rocky, Alma or RHEL 10, whose images leave out `kernel-modules-extra`
     (Docker needs its `xt_addrtype`), also the package for the connected host's running kernel. The install uses it when
     the target runs that same kernel, as a target built from the same image does.
   - Download the Harbor offline installer tarball
   - Bundle everything into `harbor-offline-package.tar.gz`

3. Transfer `harbor-offline-package.tar.gz` to the air-gapped host via USB drive, SCP over a bastion, or other secure transport.

### Installation (on the air-gapped host)

1. Extract the archive:

   ```bash
   tar xzvf harbor-offline-package.tar.gz
   ```

2. Run the installer as usual:

   ```bash
   sudo bash install_harbor.sh install-harbor
   ```

   The script automatically detects the presence of `offline-packages.tar.gz` and `VERSION.txt` inside `harbor-install-files/` and switches to offline mode. No internet access is required.

### What the Offline Package Contains

| File | Purpose |
|---|---|
| `harbor-install-files/apt-packages/offline-packages.tar.gz` | Pre-downloaded Docker CE `.deb` or `.rpm` packages |
| `harbor-install-files/apt-packages/install_packages.sh` | Package installer helper script |
| `harbor-install-files/harbor-offline-installer-v<VERSION>.tgz` | Harbor container images and installer |
| `harbor-install-files/VERSION.txt` | Marker file indicating offline mode |
| `install_harbor.sh` | This script |

### Notes for Air-Gapped Environments

- The offline package is **OS-version specific**. A package built on Ubuntu 22.04 will not work on Ubuntu 24.04 or RHEL.
- Harbor's Trivy vulnerability scanner requires database updates from the internet. In air-gapped mode, set `skip_update: true` and `offline_scan: true` in `harbor.yml` under the `trivy:` section, or manually supply the Trivy DB.
- After installation, distribute the CA certificate (`/data/ca_download/ca.crt`) to all Docker clients on the local network that need to push or pull images.

---

## Upstream / Credits

This project automates the following open-source software; all credit to their authors. See [NOTICE](NOTICE) for
the full third-party list + licenses.

- Harbor (Apache-2.0), Docker (Apache-2.0)
- The Harbor offline bundle ships several images: registry / Trivy / Notary (Apache-2.0), nginx (BSD-2-Clause), PostgreSQL (PostgreSQL License), and **Redis (license is version-dependent — verify; newer Redis may be RSALv2/SSPL, not OSI-open)**
- The air-gap bundle from `offline-prep` also holds OS packages: Docker CE, containerd, curl and what they depend on. Some are GPL or LGPL, such as iptables and GnuTLS, so its `LICENSES/` folder lists them and carries a written offer for their source

## License

Licensed under the **Apache License 2.0** — see [LICENSE](LICENSE) and [NOTICE](NOTICE).
