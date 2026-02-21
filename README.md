# Harbor Registry Installer

A single-script installer for deploying [Harbor](https://goharbor.io/) container registry with Docker Compose, self-signed TLS certificates, and systemd service management. Supports online and air-gapped installations across multiple Linux distributions.

## Features

- Automated Docker CE installation (online or offline)
- Self-signed TLS certificate generation with SAN support (IP + DNS)
- Harbor offline installer download, extraction, and configuration
- Systemd service creation for Harbor auto-start on boot
- Automatic Harbor project creation via the API
- Certificate update/rotation (self-signed or user-supplied)
- Offline package generation for air-gapped deployments
- Clean uninstall with full artifact removal
- Debug mode for verbose output

## Supported Operating Systems

| Distribution | Notes |
|---|---|
| Ubuntu | Fully supported |
| Debian | Fully supported |
| RHEL / Rocky / AlmaLinux | Docker repo via `dnf` |
| CentOS | Docker repo via `dnf` |
| Fedora | Docker repo via `dnf-3` |

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
| `HARBOR_VERSION` | `2.14.1` | Harbor release version to install |
| `HARBOR_PORT` | `443` | HTTPS port for the registry |
| `HARBOR_USERNAME` | `admin` | Admin username |
| `HARBOR_PASSWORD` | `Harbor12345` | Admin password (change after first login) |
| `DOCKER_BRIDGE_CIDR` | `172.30.0.1/16` | Custom Docker bridge network CIDR |
| `PROJECTS` | _(empty)_ | Space-separated list of Harbor projects to create |

### Certificate Configuration

| Variable | Default | Description |
|---|---|---|
| `COUNTRY` | `US` | Certificate country code |
| `STATE` | `MA` | Certificate state |
| `LOCATION` | `BOSTON` | Certificate locality |
| `ORGANIZATION` | `SELF` | Certificate organization |
| `REGISTRY_COMMON_NAME` | `regsitry.edge.lab` | FQDN for the registry certificate |
| `DURATION_DAYS` | `3650` | Certificate validity in days |

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

### Prepare Offline Package

```bash
sudo bash install_harbor.sh offline-prep
```

## Special Considerations

### Running Behind a Proxy

The generated `harbor.yml` includes a `proxy` section. If your environment requires an HTTP/HTTPS proxy, edit `/opt/harbor/harbor.yml` after installation and set `http_proxy`, `https_proxy`, and `no_proxy` under the `proxy:` block, then restart Harbor:

```bash
docker compose -f /opt/harbor/docker-compose.yml down
docker compose -f /opt/harbor/docker-compose.yml up -d
```

### DNS Resolution

Clients pulling images must be able to resolve `REGISTRY_COMMON_NAME`. If DNS is not available, add an entry to `/etc/hosts` on each client:

```
192.168.1.100  regsitry.edge.lab
```

### Trusting the Self-Signed CA on Clients

Docker clients that push/pull images from this registry need the CA certificate. After installation, the CA is available for download at `/data/ca_download/ca.crt` on the Harbor host. On each Docker client:

```bash
# Copy the CA to the client
sudo mkdir -p /etc/docker/certs.d/<REGISTRY_COMMON_NAME>:<PORT>
sudo cp ca.crt /etc/docker/certs.d/<REGISTRY_COMMON_NAME>:<PORT>/
sudo systemctl restart docker
```

### Data Persistence

Harbor stores all registry data under `/data` and configuration under `/opt/harbor`. Back up these directories before any upgrade or uninstall operation.

### Changing the Admin Password

The `HARBOR_PASSWORD` variable only sets the initial password during first installation. Change it through the Harbor web UI after deployment. Subsequent reinstalls will not update an existing password stored in the Harbor database under `/data`.

### Systemd Service

The installer creates `harbor-docker.service` so Harbor starts automatically on boot. Manage it with standard systemctl commands:

```bash
sudo systemctl status harbor-docker.service
sudo systemctl restart harbor-docker.service
sudo systemctl stop harbor-docker.service
```

### Certificate Update Behavior

The `update-certificates` command stops Harbor, replaces certificates, regenerates `harbor.yml`, and restarts the service. This causes a brief outage. The command requires either `NEW_CERT_GEN=1` or all three `USER_CERT_*` / `USER_CA_CRT` variables to be set; otherwise it exits with an error. User-supplied certificates must chain to the provided CA and are validated with `openssl verify` before installation.

## File Layout

After installation, the script creates the following structure:

```
<working-directory>/
  harbor-install-files/
    certs/                    # Generated or user-supplied certificates
      ca.crt, ca.key
      <FQDN>.crt, <FQDN>.cert, <FQDN>.key
    apt-packages/             # install_packages.sh helper
    harbor-offline-installer-v<VERSION>.tgz
    read_this_crumb.txt       # Post-install summary

/opt/harbor/                  # Harbor application
  harbor.yml                  # Harbor configuration
  docker-compose.yml          # Docker Compose file (from installer)

/data/                        # Harbor persistent data
  ca_download/ca.crt          # CA cert available for client download

/etc/docker/certs.d/<FQDN>:<PORT>/   # Docker client trust store
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
DAYS=3650
CERT_DIR="./certs"
mkdir -p $CERT_DIR

# Generate CA
openssl genrsa -out $CERT_DIR/ca.key 4096
openssl req -x509 -new -nodes -sha512 -days $DAYS \
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

# Convert to .cert for Docker
openssl x509 -inform PEM -in $CERT_DIR/$FQDN.crt -out $CERT_DIR/$FQDN.cert
```

### Step 3: Install Certificates for Docker

```bash
FQDN="registry.example.com"
PORT=443

mkdir -p /etc/docker/certs.d/$FQDN:$PORT
cp $CERT_DIR/$FQDN.cert /etc/docker/certs.d/$FQDN:$PORT/
cp $CERT_DIR/$FQDN.key  /etc/docker/certs.d/$FQDN:$PORT/
cp $CERT_DIR/ca.crt      /etc/docker/certs.d/$FQDN:$PORT/

# Make CA available for client download
mkdir -p /data/ca_download
cp $CERT_DIR/$FQDN.crt /data/ca_download/ca.crt

systemctl restart docker
```

### Step 4: Download and Extract Harbor

```bash
HARBOR_VERSION="2.14.1"
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
Type=forking
Restart=on-failure
RestartSec=5
ExecStart=/usr/bin/docker compose -f /opt/harbor/docker-compose.yml up -d
ExecStop=/usr/bin/docker compose -f /opt/harbor/docker-compose.yml down
RemainAfterExit=true

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
   - Download Docker CE packages for your OS
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
