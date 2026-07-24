#!/bin/bash

# This script contains functions for installing a Harbor registry on Ubuntu for storing container images

# Record which variables the caller explicitly set BEFORE defaults are applied, so
# recorded install-time values from .install-env can fill in unset variables without
# ever overriding an explicit user choice (precedence: env > .install-env > default)
user_set_registry_common_name=${REGISTRY_COMMON_NAME+x}
user_set_harbor_port=${HARBOR_PORT+x}
user_set_harbor_version=${HARBOR_VERSION+x}
user_set_harbor_password=${HARBOR_PASSWORD+x}
user_set_harbor_db_password=${HARBOR_DB_PASSWORD+x}

# --- User Defined Variables --- #
DEBUG=${DEBUG:-1}

# Harbor configuration
HARBOR_VERSION=${HARBOR_VERSION:-2.15.0}
HARBOR_PORT=${HARBOR_PORT:-443}
HARBOR_USERNAME=${HARBOR_USERNAME:-admin}
HARBOR_PASSWORD=${HARBOR_PASSWORD:-Harbor12345}
HARBOR_DB_PASSWORD=${HARBOR_DB_PASSWORD:-root123}
DOCKER_BRIDGE_CIDR=${DOCKER_BRIDGE_CIDR:-"172.30.0.1/16"}
PROJECTS=${PROJECTS:-""}
# uninstall-harbor: 'true' removes /data entirely; default removes only the
# Harbor-created subpaths (safe on shared /data mounts)
PURGE_DATA=${PURGE_DATA:-false}

# Self-signed certificate
COUNTRY=${COUNTRY:-"US"}
STATE=${STATE:-"MA"}
LOCATION=${LOCATION:-"BOSTON"}
ORGANIZATION=${ORGANIZATION:-"SELF"}
REGISTRY_COMMON_NAME=${REGISTRY_COMMON_NAME:-"registry.edge.lab"}
DURATION_DAYS=${DURATION_DAYS:-"3650"}

# Update certificate options
NEW_CERT_GEN=${NEW_CERT_GEN:-0}
USER_CERT_CRT=${USER_CERT_CRT:-""}
USER_CERT_KEY=${USER_CERT_KEY:-""}
USER_CA_CRT=${USER_CA_CRT:-""}

# --- INTERNAL VARIABLES (do not edit) --- #
DOCKER_PACKAGES=(docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin)
base_dir=$(pwd)
os_id=""
os_release_version=""
# First 'hostname -I' token by default; set MGMT_IP explicitly on multi-homed
# hosts to control which IP lands in the certificate SAN and the printed URLs
mgmt_ip=${MGMT_IP:-$(hostname -I | awk '{print $1}')}
mgmt_if=$(ip a |grep "$(hostname -I |awk '{print $1}')" | awk '{print $NF}')
user_name=${SUDO_USER:-$(whoami)}
current_hostname=$(hostname)
certs_dir="/opt/harbor/certs"
install_env_file="/opt/harbor/.install-env"
docker_certs_root="/etc/docker/certs.d"
data_dir="/data"
data_preexisting=0
recorded_install_files_dir=""
recorded_docker_group_added=""
recorded_install_user=""

#### --- Functions --- ###

# --- Menu Functions --- #

function install_harbor {
  if [[ -d "$data_dir/database" ]]; then
    data_preexisting=1
    echo "  NOTE: Existing Harbor data found in $data_dir."
    echo "  HARBOR_PASSWORD is only applied on the very first install - the admin"
    echo "  password already stored in $data_dir remains in effect for this install."
    echo "  Run 'uninstall-harbor' first if you need a clean install with a new password."
  fi
  run_step write_install_env
  run_step install_docker_utility
  run_step cert_gen
  run_step harbor_cert_install
  run_step gen_harbor_yml
  run_step run_harbor_installer
  run_step create_harbor_service
  run_step create_harbor_projects
  echo "# ---  Harbor Install Completed! --- #"
  echo "  Harbor install and compose files are in /opt/harbor and /data directories"
  echo "  Harbor Version: $HARBOR_VERSION"
  echo "  URL: https://$mgmt_ip:$HARBOR_PORT"
  echo "  FQDN URL: https://$REGISTRY_COMMON_NAME:$HARBOR_PORT"
  echo "  Username: $HARBOR_USERNAME"
  if [[ $data_preexisting -eq 1 ]]; then
    echo "  Password: (unchanged - the password stored in $data_dir from the prior install remains in effect)"
  else
    echo "  Password: ******** (the value passed via HARBOR_PASSWORD, or the documented default)"
  fi
}

function uninstall_harbor {
  load_install_env
  echo "  Uninstalling Harbor registry"
  echo "  Removing containers..."
  if [[ -f /etc/systemd/system/harbor-docker.service ]]; then
    systemctl disable --now harbor-docker.service 2>/dev/null || true
  fi
  if [[ -f /opt/harbor/docker-compose.yml ]] && command -v docker &> /dev/null; then
    docker compose -f /opt/harbor/docker-compose.yml down 2>/dev/null || true
  fi
  # Remove the goharbor images loaded by the Harbor offline installer
  if command -v docker &> /dev/null; then
    local goharbor_images=()
    readarray -t goharbor_images < <(docker images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | grep '^goharbor/' || true)
    if [[ ${#goharbor_images[@]} -gt 0 ]]; then
      echo "  Removing ${#goharbor_images[@]} goharbor image(s)..."
      docker rmi -f "${goharbor_images[@]}" > /dev/null 2>&1 || true
    fi
  fi
  echo "  Removing docker client trust entries..."
  rm -rf "$docker_certs_root/$REGISTRY_COMMON_NAME:$HARBOR_PORT"
  sweep_matching_certsd_dirs
  echo "  Removing data files..."
  # Remove the install files where they were recorded at install time (works
  # from any cwd), plus a cwd copy when both exist
  if [[ -n "$recorded_install_files_dir" && -d "$recorded_install_files_dir" ]]; then
    rm -rf "$recorded_install_files_dir"
  fi
  rm -rf "$base_dir/harbor-install-files"
  remove_harbor_data
  rm -rf /var/log/harbor
  rm -f /etc/systemd/system/harbor-docker.service
  systemctl daemon-reload
  systemctl reset-failed harbor-docker.service 2>/dev/null || true
  # Remove the docker group membership only when this installer added it
  if [[ "$recorded_docker_group_added" == "1" && -n "$recorded_install_user" ]]; then
    if id -nG "$recorded_install_user" 2>/dev/null | tr ' ' '\n' | grep -qx docker; then
      gpasswd -d "$recorded_install_user" docker > /dev/null 2>&1 || true
      echo "  Removed $recorded_install_user from the docker group (membership was added by the installer)"
    fi
  fi
  rm -rf /opt/harbor
  echo "  Uninstallation completed..."
}

function sweep_matching_certsd_dirs () {
  # Fallback for installs made before .install-env existed: remove exactly the
  # certs.d entries whose ca.crt byte-matches the CA this installer created
  local installed_ca="$certs_dir/ca.crt"
  [[ -f "$installed_ca" ]] || return 0
  local dir
  for dir in "$docker_certs_root"/*/; do
    [[ -d "$dir" ]] || continue
    [[ -f "$dir/ca.crt" ]] || continue
    if cmp -s "$dir/ca.crt" "$installed_ca"; then
      rm -rf "$dir"
      echo "  Removed ${dir%/} (its ca.crt matches the installed Harbor CA)"
    fi
  done
}

function remove_harbor_data () {
  # Never remove $data_dir wholesale by default - /data can be a shared mount
  # holding non-Harbor data. PURGE_DATA=true opts in to full removal.
  if [[ "$PURGE_DATA" == "true" || "$PURGE_DATA" == "1" ]]; then
    echo "  PURGE_DATA=$PURGE_DATA - removing $data_dir entirely"
    rm -rf "$data_dir"
    return 0
  fi
  local harbor_subdirs=(ca_download database job_logs redis registry secret trivy-adapter chart_storage)
  local sub
  for sub in "${harbor_subdirs[@]}"; do
    [[ -e "$data_dir/$sub" ]] && rm -rf "${data_dir:?}/$sub"
  done
  rmdir "$data_dir" 2>/dev/null || true
  echo "  Removed Harbor-created paths under $data_dir (set PURGE_DATA=true to remove $data_dir entirely)"
}

function harbor_offline_prep {
  echo "  Preparing an offline package for Harbor registry..."
  run_step apt_download_packs
  run_step download_harbor_offline_package
  run_step prepare_offline_package
  echo "  Offline package generation completed..."
  echo "  Upload harbor-offline-package.tar.gz to your airgapped system running $os_release_version"
}



function update_certificates {
  if [[ ! -f /opt/harbor/docker-compose.yml || ! -x /opt/harbor/prepare ]]; then
    echo "  ERROR: No Harbor installation found in /opt/harbor. Run install-harbor first."
    exit 1
  fi
  load_install_env
  preserve_existing_yml_passwords
  echo "  Stopping Harbor containers..."
  if [[ -f /etc/systemd/system/harbor-docker.service ]]; then
    systemctl stop harbor-docker.service || true
  fi
  docker compose -f /opt/harbor/docker-compose.yml down || true
  run_step new_cert_check
  run_step harbor_cert_install
  run_step gen_harbor_yml
  # Harbor's nginx config is rendered from harbor.yml by prepare - without this
  # the stack keeps serving the old certificate
  echo "  Running Harbor prepare to apply the new certificates..."
  run_step run_harbor_prepare
  echo "  Starting Harbor containers..."
  if [[ -f /etc/systemd/system/harbor-docker.service ]]; then
    if ! systemctl start harbor-docker.service; then
      echo "ERROR: Failed to start harbor-docker.service after the certificate update."
      exit 1
    fi
  else
    if ! docker compose -f /opt/harbor/docker-compose.yml up -d; then
      echo "ERROR: Failed to start the Harbor stack after the certificate update."
      exit 1
    fi
  fi
  run_step verify_served_certificate
  # Display new certificate expiry
  local cert_expiry
  cert_expiry=$(openssl x509 -noout -enddate -in "$certs_dir/$REGISTRY_COMMON_NAME.crt" 2>/dev/null | cut -d= -f2)
  echo "# --- Certificate Update Completed! --- #"
  echo "  Certificate expires: $cert_expiry"
  echo "  Registry: https://$REGISTRY_COMMON_NAME:$HARBOR_PORT"
}

# --- Install Harbor Functions --- #

os_type() {
    # Get OS information from /etc/os-release
    if [[ -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
        source /etc/os-release
        echo "  OS type is: $ID"
        os_id="$ID"
        os_release_version="$ID-${VERSION_ID:-unknown}"
    else
        echo "Unknown or unsupported OS $os_id."
        exit 1
    fi
}

# Function to check required commands up front, with a distro install hint
# (minimal cloud images frequently lack curl)
require_cmds() {
    local missing=()
    local cmd
    for cmd in "$@"; do
        if ! command -v "$cmd" &> /dev/null; then
            missing+=("$cmd")
        fi
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo "Error: Required command(s) not found: ${missing[*]}"
        case "$os_id" in
            ubuntu|debian)
                echo "  Hint: apt-get update && apt-get install -y ${missing[*]}"
                ;;
            rhel|centos|rocky|almalinux|fedora)
                echo "  Hint: dnf install -y ${missing[*]}"
                ;;
            sles|opensuse-leap)
                echo "  Hint: zypper install -y ${missing[*]}"
                ;;
        esac
        exit 1
    fi
}

function preflight_checks () {
  # Verify the commands this subcommand will need before doing any work
  local required_cmds=()
  case "$1" in
    install)
      required_cmds=(tar openssl)
      # Online mode needs to fetch install_packages.sh and the Harbor installer
      [[ -f "$base_dir/harbor-install-files/VERSION.txt" ]] || required_cmds+=(curl)
      ;;
    offline-prep)
      required_cmds=(tar curl)
      ;;
    update-certificates)
      required_cmds=(openssl)
      ;;
  esac
  require_cmds "${required_cmds[@]}"
}

function select_docker_packages () {
    # Pick the per-distro docker package list up front so every path (online
    # install, air-gapped install, and save) uses the correct names. Docker CE
    # is not published for the SUSE family; the distro packages are used
    # (docker-compose is a separate package there, and Harbor requires compose).
    case "$os_id" in
        sles|opensuse-leap)
            DOCKER_PACKAGES=(docker docker-compose)
            ;;
    esac
}

function ensure_dnf_config_manager () {
    # 'dnf config-manager' is provided by dnf-plugins-core, which is absent on
    # minimal images
    if ! dnf config-manager --help &> /dev/null; then
        echo "  Installing dnf-plugins-core (provides 'dnf config-manager')"
        if ! dnf install -y dnf-plugins-core; then
            echo "Error: Failed to install dnf-plugins-core (required for 'dnf config-manager')."
            return 1
        fi
    fi
}

function ensure_docker_repo () {
    # Only (re)add the docker repository when it is not already configured
    case "$os_id" in
        ubuntu|debian)
            [[ -f /etc/apt/sources.list.d/docker.list ]] || add_docker_repo
            ;;
        rhel|centos|rocky|almalinux|fedora)
            [[ -f /etc/yum.repos.d/docker-ce.repo ]] || add_docker_repo
            ;;
        sles|opensuse-leap)
            : # distro repositories already provide the docker packages
            ;;
        *)
            add_docker_repo
            ;;
    esac
}

function add_docker_repo () {
    echo "Adding docker repo..."
    case "$os_id" in
        ubuntu)
            install -m 0755 -d /etc/apt/keyrings
            curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
            chmod a+r /etc/apt/keyrings/docker.asc
            echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}") stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
            ;;
        debian)
            install -m 0755 -d /etc/apt/keyrings
            curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
            chmod a+r /etc/apt/keyrings/docker.asc
            echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
            ;;
        rhel)
            ensure_dnf_config_manager || return 1
            dnf config-manager --add-repo https://download.docker.com/linux/rhel/docker-ce.repo
            ;;
        rocky|almalinux|centos)
            # Docker designates the 'centos' repo path for CentOS/Rocky/Alma
            ensure_dnf_config_manager || return 1
            dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
            ;;
        fedora)
            dnf-3 config-manager --add-repo https://download.docker.com/linux/fedora/docker-ce.repo
            ;;
        sles|opensuse-leap)
            : # no Docker CE repo for SUSE; the distro docker packages are used
            ;;
        *)
            echo "Error: Unsupported OS '$os_id'. Manual install of Docker required."
            return 1
            ;;
    esac
}

function install_packages_check () {
    # Refetch when the cached copy is missing or zero-byte (a previously failed
    # download must never be reused)
    local dest="$base_dir/harbor-install-files/apt-packages/install_packages.sh"
    if [[ ! -s "$dest" ]]; then
        mkdir -p "$base_dir/harbor-install-files/apt-packages"
        rm -f "$dest"
        echo "  Downloading install_packages.sh..."
        if ! curl -fsSL https://github.com/Chubtoad5/install-packages/raw/refs/heads/main/install_packages.sh -o "$dest"; then
            echo "Error: Failed to download install_packages.sh."
            rm -f "$dest"
            return 1
        fi
        chmod +x "$dest"
    fi
}

function install_docker_utility() {
    install_packages_check || return 1
    create_bridge_json || return 1
    cd "$base_dir/harbor-install-files/apt-packages" || return 1
    if [[ -f "$base_dir/harbor-install-files/apt-packages/offline-packages.tar.gz" ]]; then
        ./install_packages.sh offline "${DOCKER_PACKAGES[@]}" || { cd "$base_dir"; return 1; }
    else
        ensure_docker_repo || { cd "$base_dir"; return 1; }
        ./install_packages.sh online "${DOCKER_PACKAGES[@]}" || { cd "$base_dir"; return 1; }
    fi
    cd "$base_dir" || return 1
    if ! command -v docker &> /dev/null; then
        echo "Error: Docker installation failed."
        return 1
    fi
    if ! systemctl enable --now docker; then
        echo "Error: Failed to enable and start the docker service."
        return 1
    fi
    if ! systemctl is-active --quiet docker; then
        echo "Error: The docker service is not active after 'systemctl enable --now docker'."
        return 1
    fi
    # Record whether this run added the docker group membership so uninstall
    # removes only what the installer added
    if id -nG "$user_name" 2>/dev/null | tr ' ' '\n' | grep -qx docker; then
        echo "  User $user_name is already in the docker group"
    else
        usermod -aG docker "$user_name"
        set_install_env_value DOCKER_GROUP_ADDED 1
    fi
}

function create_bridge_json () {
  # Merge bip into an existing daemon.json instead of clobbering it - /etc/docker
  # can hold settings this script does not own (synced from images-pull-push)
  mkdir -p /etc/docker
  if [[ -f /etc/docker/daemon.json ]]; then
      if grep -q '"bip"' /etc/docker/daemon.json; then
          echo "  Existing /etc/docker/daemon.json already defines \"bip\", leaving it unchanged"
          return 0
      fi
      local backup
      backup=$(mktemp)
      cp /etc/docker/daemon.json "$backup"
      if command -v jq &> /dev/null; then
          if ! jq --arg bip "$DOCKER_BRIDGE_CIDR" '. + {bip: $bip}' "$backup" > /etc/docker/daemon.json; then
              cp "$backup" /etc/docker/daemon.json
              rm -f "$backup"
              echo "Error: Failed to merge bip into existing /etc/docker/daemon.json."
              return 1
          fi
      elif command -v python3 &> /dev/null; then
          if ! python3 -c 'import json,sys; p="/etc/docker/daemon.json"; d=json.load(open(p)); d["bip"]=sys.argv[1]; f=open(p,"w"); json.dump(d,f,indent=2); f.write("\n")' "$DOCKER_BRIDGE_CIDR"; then
              cp "$backup" /etc/docker/daemon.json
              rm -f "$backup"
              echo "Error: Failed to merge bip into existing /etc/docker/daemon.json."
              return 1
          fi
      else
          echo "Warning: /etc/docker/daemon.json exists but neither jq nor python3 is available to merge \"bip\": \"$DOCKER_BRIDGE_CIDR\"."
          echo "         Leaving the existing file unchanged; set bip manually if a custom docker bridge CIDR is required."
          rm -f "$backup"
          return 0
      fi
      rm -f "$backup"
      echo "  Merged bip: $DOCKER_BRIDGE_CIDR into existing /etc/docker/daemon.json"
  else
      cat <<EOF | tee /etc/docker/daemon.json > /dev/null
{
  "bip": "$DOCKER_BRIDGE_CIDR"
}
EOF
      echo "  Created /etc/docker/daemon.json with bip: $DOCKER_BRIDGE_CIDR"
  fi
}

function ca_gen () {
  # Generate the CA pair only when one does not already exist. Reusing the CA on
  # re-install and cert renewal keeps every remote client's trust intact.
  if [[ -s "$certs_dir/ca.crt" && -s "$certs_dir/ca.key" ]]; then
    echo "  Existing CA found in $certs_dir - reusing it (remote client trust is preserved)"
    return 0
  fi
  if [[ -s "$certs_dir/ca.crt" || -s "$certs_dir/ca.key" ]]; then
    echo "  ERROR: Incomplete CA in $certs_dir (one of ca.crt/ca.key is missing or empty)."
    echo "  Restore the missing file, or remove both to generate a fresh CA (remote clients must then re-trust it)."
    return 1
  fi
  echo "  Generating a new certificate authority (valid $DURATION_DAYS days)..."
  mkdir -p "$certs_dir"
  # Generate CA key
  openssl genrsa -out "$certs_dir/ca.key" 4096 || return 1
  # Generate CA certificate
  openssl req -x509 -new -nodes -sha512 -days "$DURATION_DAYS" -subj "/C=$COUNTRY/ST=$STATE/L=$LOCATION/O=$ORGANIZATION/CN=$REGISTRY_COMMON_NAME" -key "$certs_dir/ca.key" -out "$certs_dir/ca.crt" || return 1
}

function server_cert_gen () {
  echo "  Creating server certificate valid for $DURATION_DAYS days (signed by the CA in $certs_dir)..."
  mkdir -p "$certs_dir"
  # Generate server key
  openssl genrsa -out "$certs_dir/$REGISTRY_COMMON_NAME.key" 4096 || return 1
  # Generate server CSR
  openssl req -sha512 -new -subj "/C=$COUNTRY/ST=$STATE/L=$LOCATION/O=$ORGANIZATION/CN=$REGISTRY_COMMON_NAME" -key "$certs_dir/$REGISTRY_COMMON_NAME.key" -out "$certs_dir/$REGISTRY_COMMON_NAME.csr" || return 1
  # Create v3 extension
  cat > "$certs_dir/v3.ext" <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
IP.1=$mgmt_ip
DNS.1=$REGISTRY_COMMON_NAME
DNS.2=$current_hostname
EOF

  # Generate signed certificate
  openssl x509 -req -sha512 -days "$DURATION_DAYS" -extfile "$certs_dir/v3.ext" -CA "$certs_dir/ca.crt" -CAkey "$certs_dir/ca.key" -CAcreateserial -in "$certs_dir/$REGISTRY_COMMON_NAME.csr" -out "$certs_dir/$REGISTRY_COMMON_NAME.crt" || return 1
  # Convert signed certificate from .crt to .cert
  openssl x509 -inform PEM -in "$certs_dir/$REGISTRY_COMMON_NAME.crt" -out "$certs_dir/$REGISTRY_COMMON_NAME.cert" || return 1
  # Create fullchain (server cert + CA cert) so nginx sends the complete chain during TLS handshake
  cat "$certs_dir/$REGISTRY_COMMON_NAME.crt" "$certs_dir/ca.crt" > "$certs_dir/$REGISTRY_COMMON_NAME-fullchain.crt"
  echo "Certificate generation completed..."
}

function cert_gen () {
  ca_gen || return 1
  server_cert_gen || return 1
}

function harbor_cert_install () {
  # Copy certs - only client trust material belongs in certs.d, never the
  # private key
  mkdir -p "$data_dir/ca_download"
  mkdir -p "$docker_certs_root/$REGISTRY_COMMON_NAME:$HARBOR_PORT"
  cp "$certs_dir/ca.crt" "$docker_certs_root/$REGISTRY_COMMON_NAME:$HARBOR_PORT/" || return 1
  # Remove private keys leaked into certs.d by pre-fix installs, and server
  # .cert files copied by pre-fix installs: docker treats .cert/.key as a
  # CLIENT certificate pair, so an orphaned .cert (key no longer copied)
  # makes every docker login fail with "missing key <name>.key"
  rm -f "$docker_certs_root/$REGISTRY_COMMON_NAME:$HARBOR_PORT"/*.key \
        "$docker_certs_root/$REGISTRY_COMMON_NAME:$HARBOR_PORT"/*.cert
  # Copy the actual CA certificate (not the server cert) to ca_download for external consumers
  cp "$certs_dir/ca.crt" "$data_dir/ca_download/ca.crt" || return 1

  # Record the CA fingerprint so uninstall can identify this install's trust entries
  set_install_env_value CA_FINGERPRINT "$(openssl x509 -noout -fingerprint -sha256 -in "$certs_dir/ca.crt" 2>/dev/null | cut -d= -f2)"

  # Restart docker
  if ! systemctl restart docker; then
    echo "Error: Failed to restart docker after installing certificates."
    return 1
  fi
}

function run_harbor_installer() {
  local installer_tgz="$base_dir/harbor-install-files/harbor-offline-installer-v$HARBOR_VERSION.tgz"
  if [ -f "$base_dir/harbor-install-files/VERSION.txt" ]; then
    if [[ ! -s "$installer_tgz" ]]; then
      echo "Error: $installer_tgz is missing or empty in this offline bundle."
      return 1
    fi
  else
    download_harbor_offline_package || return 1
  fi
  tar xzvf "$installer_tgz" -C /opt/ || return 1
  /opt/harbor/install.sh || return 1
  echo "  creating crumb file..."
  # No credentials in the crumb file - it is a plaintext breadcrumb, not a vault
  cat > "$base_dir/harbor-install-files/read_this_crumb.txt" <<EOF
Harbor install files are located in /opt/harbor and /data directories
Version: $HARBOR_VERSION
URL: https://$mgmt_ip:$HARBOR_PORT
FQDN URL: https://$REGISTRY_COMMON_NAME:$HARBOR_PORT
Default Username: $HARBOR_USERNAME
Password: (not stored here - the admin password set at install time is in effect)
EOF
  chmod 600 "$base_dir/harbor-install-files/read_this_crumb.txt"
}

function create_harbor_service () {
    echo "  Creating Habor systemd service..."
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
    systemctl enable --now harbor-docker.service || return 1
}


# --- Offline Prep Functions --- #

function apt_download_packs () {
  install_packages_check || return 1
  ensure_docker_repo || return 1
  cd "$base_dir/harbor-install-files/apt-packages" || return 1
  if ! ./install_packages.sh save "${DOCKER_PACKAGES[@]}"; then
    echo "Error: install_packages.sh failed to save the docker packages (${DOCKER_PACKAGES[*]})."
    cd "$base_dir"
    return 1
  fi
  # Verify a usable package archive was actually produced - the offline package
  # contract includes offline-packages.tar.gz
  if [[ ! -s offline-packages.tar.gz ]] || ! tar -tzf offline-packages.tar.gz 2>/dev/null | grep -qE '\.(deb|rpm)$'; then
    echo "Error: offline-packages.tar.gz was not produced or contains no .deb/.rpm packages."
    cd "$base_dir"
    return 1
  fi
  cd "$base_dir" || return 1
}

function download_harbor_offline_package() {
  local installer_tgz="$base_dir/harbor-install-files/harbor-offline-installer-v$HARBOR_VERSION.tgz"
  # Refetch when a previous download left a zero-byte file
  [[ -f "$installer_tgz" && ! -s "$installer_tgz" ]] && rm -f "$installer_tgz"
  if [[ -f "$installer_tgz" ]]; then
    echo "  Harbor offline installer already downloaded."
    return 0
  fi
  if ! curl -fsSLo "$installer_tgz" "https://github.com/goharbor/harbor/releases/download/v$HARBOR_VERSION/harbor-offline-installer-v$HARBOR_VERSION.tgz"; then
    echo "Error: Failed to download the Harbor offline installer v$HARBOR_VERSION."
    rm -f "$installer_tgz"
    return 1
  fi
}

function generate_bundle_licenses() {
  # Write a LICENSES/ third-party manifest into the offline archive. Harbor and its
  # components are Apache-2.0; the offline tgz ships several images under their own
  # licenses (notably Redis, whose license is version-dependent). No GPL/AGPL is
  # bundled, so no written source offer is required.
  local dir="$base_dir/LICENSES"
  rm -rf "$dir"; mkdir -p "$dir"
  cat > "$dir/THIRD_PARTY_NOTICES.txt" <<EOF
Third-party components redistributed in this Harbor air-gap bundle
Generated: $(date)
Harbor version: $HARBOR_VERSION

Harbor and its components are Apache-2.0 (https://github.com/goharbor/harbor). The
offline installer (harbor-offline-installer-v$HARBOR_VERSION.tgz) ships multiple upstream
container images, each carrying its own license inside the image, e.g.:

  registry / distribution ... Apache-2.0
  Trivy ..................... Apache-2.0   https://github.com/aquasecurity/trivy
  Notary ................... Apache-2.0
  nginx (proxy) ............ BSD-2-Clause  https://nginx.org/
  PostgreSQL ............... PostgreSQL License
  Redis (goharbor/redis-photon) BSD-3-Clause for Harbor 2.15.x: it ships Redis 7.2,
                            which is BSD-3-Clause (permissive). NOTE: Redis 7.4+ moved to
                            RSALv2/SSPL (source-available, NOT OSI) and 8.0+ added AGPLv3 —
                            re-verify if you bump HARBOR_VERSION to a release whose
                            redis-photon ships Redis 7.4 or newer.

Docker CE packages installed on the host are Apache-2.0. The installer script is
Apache-2.0 (Chubtoad5). No GPL/AGPL components are bundled, so no written source offer
is required; each image's own license/notice ships inside the image.
EOF
  echo "  Wrote LICENSES/ (third-party manifest)."
}

function prepare_offline_package() {
  echo "  Generating offline archive..."
  cd "$base_dir" || return 1
  echo "Offline package generated on $(date) for $os_release_version and Harbor version $HARBOR_VERSION" | tee "$base_dir/harbor-install-files/VERSION.txt"
  generate_bundle_licenses
  tar czvf harbor-offline-package.tar.gz harbor-install-files/ install_harbor.sh LICENSES || return 1
}

# --- Update Certificate Functions --- #

function new_cert_check() {
  if [[ "$NEW_CERT_GEN" -eq 1 ]]; then
    echo "  Generating new self-signed certificate (existing CA is reused when present)..."
    cert_gen || return 1
  elif [[ -n "$USER_CERT_CRT" && -n "$USER_CERT_KEY" && -n "$USER_CA_CRT" ]]; then
    echo "  Using user-supplied certificates..."
    # Validate files exist
    for f in "$USER_CERT_CRT" "$USER_CERT_KEY" "$USER_CA_CRT"; do
      if [[ ! -f "$f" ]]; then
        echo "  ERROR: Certificate file not found: $f"
        return 1
      fi
    done
    # Verify the certificate is readable
    if ! openssl x509 -noout -subject -in "$USER_CERT_CRT" > /dev/null 2>&1; then
      echo "  ERROR: Unable to read certificate: $USER_CERT_CRT"
      return 1
    fi
    # Verify the certificate chains to the provided CA
    if ! openssl verify -CAfile "$USER_CA_CRT" "$USER_CERT_CRT" > /dev/null 2>&1; then
      echo "  ERROR: Certificate verification failed. Cert does not chain to provided CA."
      return 1
    fi
    echo "  Certificate validation passed."
    # Copy user-supplied files into expected locations
    mkdir -p "$certs_dir"
    cp "$USER_CA_CRT" "$certs_dir/ca.crt"
    cp "$USER_CERT_CRT" "$certs_dir/$REGISTRY_COMMON_NAME.crt"
    cp "$USER_CERT_KEY" "$certs_dir/$REGISTRY_COMMON_NAME.key"
    # Convert .crt to .cert for Docker
    openssl x509 -inform PEM -in "$USER_CERT_CRT" -out "$certs_dir/$REGISTRY_COMMON_NAME.cert"
    # Create fullchain (server cert + CA cert) so nginx sends the complete chain during TLS handshake
    cat "$certs_dir/$REGISTRY_COMMON_NAME.crt" "$certs_dir/ca.crt" > "$certs_dir/$REGISTRY_COMMON_NAME-fullchain.crt"
    echo "  User-supplied certificates installed to $certs_dir/"
  else
    echo "  ERROR: No certificate source specified."
    echo "  Set NEW_CERT_GEN=1 to generate a new self-signed certificate,"
    echo "  or provide USER_CERT_CRT, USER_CERT_KEY, and USER_CA_CRT for user-supplied certificates."
    return 1
  fi
}

function preserve_existing_yml_passwords () {
  # update-certificates regenerates harbor.yml - keep the passwords the running
  # install uses unless the caller explicitly re-passed them
  [[ -f /opt/harbor/harbor.yml ]] || return 0
  local current
  if [[ -z "$user_set_harbor_password" ]]; then
    current=$(sed -n 's/^harbor_admin_password: "\(.*\)"$/\1/p' /opt/harbor/harbor.yml | head -n 1)
    [[ -n "$current" ]] && HARBOR_PASSWORD="$current"
  fi
  if [[ -z "$user_set_harbor_db_password" ]]; then
    current=$(awk '/^database:/{f=1;next} /^[^ #]/{f=0} f && $1=="password:"{print $2; exit}' /opt/harbor/harbor.yml)
    [[ -n "$current" ]] && HARBOR_DB_PASSWORD="$current"
  fi
}

function run_harbor_prepare () {
  if [[ ! -x /opt/harbor/prepare ]]; then
    echo "Error: /opt/harbor/prepare not found - is Harbor installed?"
    return 1
  fi
  /opt/harbor/prepare || return 1
}

function verify_served_certificate () {
  # Truthfully verify nginx is actually serving the certificate on disk
  local expected served attempt max_attempts=12 wait_seconds=5
  expected=$(openssl x509 -noout -fingerprint -sha256 -in "$certs_dir/$REGISTRY_COMMON_NAME.crt" 2>/dev/null | cut -d= -f2)
  if [[ -z "$expected" ]]; then
    echo "Error: Unable to read $certs_dir/$REGISTRY_COMMON_NAME.crt to verify the served certificate."
    return 1
  fi
  echo "  Verifying the registry is serving the new certificate..."
  for ((attempt=1; attempt<=max_attempts; attempt++)); do
    served=$(echo | openssl s_client -connect "$mgmt_ip:$HARBOR_PORT" -servername "$REGISTRY_COMMON_NAME" 2>/dev/null \
        | openssl x509 -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2)
    if [[ -n "$served" && "$served" == "$expected" ]]; then
      echo "  Verified: the served certificate matches $certs_dir/$REGISTRY_COMMON_NAME.crt"
      return 0
    fi
    echo "  Attempt $attempt/$max_attempts: served certificate does not match yet. Retrying in ${wait_seconds}s..."
    sleep "$wait_seconds"
  done
  echo "Error: The registry is NOT serving the expected certificate after $((max_attempts * wait_seconds))s."
  return 1
}

# --- Install-State Functions --- #

function write_install_env () {
  # FIRST mutating step of install: record the install-time values (never the
  # password) so uninstall and update-certificates operate on what was actually
  # installed, not on whatever the current environment defaults to
  mkdir -p "$(dirname "$install_env_file")"
  cat > "$install_env_file" <<EOF
# Harbor install-time state - written by install_harbor.sh (no secrets stored here)
# Consumed by uninstall-harbor and update-certificates. Do not edit.
REGISTRY_COMMON_NAME=$REGISTRY_COMMON_NAME
HARBOR_PORT=$HARBOR_PORT
HARBOR_VERSION=$HARBOR_VERSION
INSTALL_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)
INSTALL_USER=$user_name
INSTALL_FILES_DIR=$base_dir/harbor-install-files
DOCKER_GROUP_ADDED=0
CA_FINGERPRINT=
EOF
  chmod 600 "$install_env_file"
  echo "  Recorded install-time state in $install_env_file"
}

function get_install_env_value () {
  [[ -f "$install_env_file" ]] || return 0
  sed -n "s|^$1=||p" "$install_env_file" | head -n 1
}

function set_install_env_value () {
  local key="$1" value="$2"
  [[ -f "$install_env_file" ]] || return 0
  if grep -q "^$key=" "$install_env_file"; then
    sed -i "s|^$key=.*|$key=$value|" "$install_env_file"
  else
    echo "$key=$value" >> "$install_env_file"
  fi
}

function load_install_env () {
  # Fill in values recorded at install time. Precedence: explicitly-set
  # environment > .install-env > script default.
  [[ -f "$install_env_file" ]] || return 0
  local recorded
  if [[ -z "$user_set_registry_common_name" ]]; then
    recorded=$(get_install_env_value REGISTRY_COMMON_NAME)
    [[ -n "$recorded" ]] && REGISTRY_COMMON_NAME="$recorded"
  fi
  if [[ -z "$user_set_harbor_port" ]]; then
    recorded=$(get_install_env_value HARBOR_PORT)
    [[ -n "$recorded" ]] && HARBOR_PORT="$recorded"
  fi
  if [[ -z "$user_set_harbor_version" ]]; then
    recorded=$(get_install_env_value HARBOR_VERSION)
    [[ -n "$recorded" ]] && HARBOR_VERSION="$recorded"
  fi
  recorded_install_files_dir=$(get_install_env_value INSTALL_FILES_DIR)
  recorded_docker_group_added=$(get_install_env_value DOCKER_GROUP_ADDED)
  recorded_install_user=$(get_install_env_value INSTALL_USER)
  echo "  Using install-time state from $install_env_file (REGISTRY_COMMON_NAME=$REGISTRY_COMMON_NAME, HARBOR_PORT=$HARBOR_PORT)"
}

# --- Utility Functions --- #

function debug_run() {
  if [ "$DEBUG" -eq 1 ]; then
    echo "--- DEBUG: Running '$*' ---"
    "$@"
    local status=$?
    echo "--- DEBUG: Finished '$*' with status $status ---"
    return $status
  else
    echo "Running '$*'..."
    "$@" > /dev/null 2>&1
    return $?
  fi
}

function run_step() {
  # Phase boundary: a failed step must fail the whole run - never print a green
  # completion banner (or exit 0) over a failed install
  if ! debug_run "$@"; then
    echo "ERROR: Step '$1' failed. Aborting - see the output above for details." >&2
    exit 1
  fi
}

create_harbor_projects() {
    local max_attempts=12
    local wait_seconds=5
    local attempt=1
    local connected=false
    local health_status=""
    local rc=0
    local curl_cfg
    read -r -a PROJECTS_ARRAY <<< "$PROJECTS"
    # Keep credentials off argv: pass them to curl via a root-only config file
    curl_cfg=$(mktemp)
    chmod 600 "$curl_cfg"
    printf 'user = "%s:%s"\n' "$HARBOR_USERNAME" "$HARBOR_PASSWORD" > "$curl_cfg"
    # 1. Connectivity & Auth Pre-Check with Retry Loop
    echo "  Starting Harbor API health check (Timeout: $((max_attempts * wait_seconds))s)..."

    while [ $attempt -le $max_attempts ]; do
        health_status=$(curl -s -o /dev/null -w "%{http_code}" \
            -K "$curl_cfg" -k \
            "https://$mgmt_ip:$HARBOR_PORT/api/v2.0/projects?page_size=1")

        if [[ "$health_status" == "200" ]]; then
            echo "  Connection successful on attempt $attempt."
            connected=true
            break
        fi

        echo "  Attempt $attempt/$max_attempts: Harbor API not ready (Status: $health_status). Retrying in ${wait_seconds}s..."
        sleep $wait_seconds
        ((attempt++))
    done

    if [ "$connected" = false ]; then
        rm -f "$curl_cfg"
        if [[ "$health_status" == "401" ]]; then
            echo "  CRITICAL: Harbor API rejected the credentials (HTTP 401)."
            if [[ $data_preexisting -eq 1 ]]; then
                echo "  This install reused existing Harbor data in $data_dir - the ORIGINAL admin password is in effect, not the HARBOR_PASSWORD passed to this run."
            fi
        else
            echo "  CRITICAL: Harbor API remained unreachable after $((max_attempts * wait_seconds)) seconds (last status: $health_status)."
        fi
        return 1
    fi

    # 2. Loop through the PROJECTS array
    if [[ -z "${PROJECTS_ARRAY[*]}" ]]; then
        echo "  No projects defined in the list. Skipping project creation..."
        rm -f "$curl_cfg"
        return 0
    fi
    echo "  Found projects to create"
    for REGISTRY_PROJECT_NAME in "${PROJECTS_ARRAY[@]}"; do
        echo "  Processing project: $REGISTRY_PROJECT_NAME"

        # Check if project exists
        local exists
        exists=$(curl -s -K "$curl_cfg" -k "https://$mgmt_ip:$HARBOR_PORT/api/v2.0/projects?name=$REGISTRY_PROJECT_NAME" \
            | grep -o "\"name\":\"$REGISTRY_PROJECT_NAME\"" | awk -F':' '{print $2}' | tr -d '"')

        if [[ "$exists" == "$REGISTRY_PROJECT_NAME" ]]; then
            echo "  Result: Project '$REGISTRY_PROJECT_NAME' already exists."
        else
            # 3. Create the project
            local create_status
            create_status=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
                -H "Content-Type: application/json" \
                -K "$curl_cfg" \
                -k -d "{ \"project_name\": \"$REGISTRY_PROJECT_NAME\", \"public\": false }" \
                "https://$mgmt_ip:$HARBOR_PORT/api/v2.0/projects")

            # 4. Final Verification
            local verified
            verified=$(curl -s -K "$curl_cfg" -k "https://$mgmt_ip:$HARBOR_PORT/api/v2.0/projects?name=$REGISTRY_PROJECT_NAME" \
                | grep -o "\"name\":\"$REGISTRY_PROJECT_NAME\"" | awk -F':' '{print $2}' | tr -d '"')

            if [[ "$verified" == "$REGISTRY_PROJECT_NAME" ]]; then
                echo "  Success: Project '$REGISTRY_PROJECT_NAME' verified (HTTP $create_status)."
            else
                echo "  Failure: Project '$REGISTRY_PROJECT_NAME' creation failed (HTTP $create_status)."
                rc=1
            fi
        fi
    done
    rm -f "$curl_cfg"
    if [[ $rc -ne 0 ]]; then
        echo "  One or more projects could not be created."
        return 1
    fi
    echo "  All project checks and creations completed successfully."
}

function check_root_privileges() {
  if [[ $EUID != 0 ]]; then
    echo "This script must be run with sudo or as the root user."
    exit 1
  fi
}

# --- File Generation Functions --- #

function gen_harbor_yml () {
  mkdir -p /opt/harbor
  cat > /opt/harbor/harbor.yml <<EOF
# Configuration file of Harbor

# The IP address or hostname to access admin UI and registry service.
# DO NOT use localhost or 127.0.0.1, because Harbor needs to be accessed by external clients.
hostname: $REGISTRY_COMMON_NAME

# http related config
http:
  # port for http, default is 80. If https enabled, this port will redirect to https port
  port: 80

# https related config
https:
  # https port for harbor, default is 443
  port: $HARBOR_PORT
  # The path of cert and key files for nginx
  certificate: "/opt/harbor/certs/$REGISTRY_COMMON_NAME-fullchain.crt"
  private_key: "/opt/harbor/certs/$REGISTRY_COMMON_NAME.key"
  # enable strong ssl ciphers (default: false)
  # strong_ssl_ciphers: false

# # Harbor will set ipv4 enabled only by default if this block is not configured
# # Otherwise, please uncomment this block to configure your own ip_family stacks
# ip_family:
#   # ipv6Enabled set to true if ipv6 is enabled in docker network, currently it affected the nginx related component
#   ipv6:
#     enabled: false
#   # ipv4Enabled set to true by default, currently it affected the nginx related component
#   ipv4:
#     enabled: true

# # Uncomment following will enable tls communication between all harbor components
# internal_tls:
#   # set enabled to true means internal tls is enabled
#   enabled: true
#   # put your cert and key files on dir
#   dir: /etc/harbor/tls/internal


# Uncomment external_url if you want to enable external proxy
# And when it enabled the hostname will no longer used
# external_url: https://reg.mydomain.com:8433

# The initial password of Harbor admin
# It only works in first time to install harbor
# Remember Change the admin password from UI after launching Harbor.
harbor_admin_password: "$HARBOR_PASSWORD"

# Harbor DB configuration
database:
  # The password for the user('postgres' by default) of Harbor DB. Change this before any production use.
  password: $HARBOR_DB_PASSWORD
  # The maximum number of connections in the idle connection pool. If it <=0, no idle connections are retained.
  max_idle_conns: 100
  # The maximum number of open connections to the database. If it <= 0, then there is no limit on the number of open connections.
  # Note: the default number of connections is 1024 for postgres of harbor.
  max_open_conns: 900
  # The maximum amount of time a connection may be reused. Expired connections may be closed lazily before reuse. If it <= 0, connections are not closed due to a connection's age.
  # The value is a duration string. A duration string is a possibly signed sequence of decimal numbers, each with optional fraction and a unit suffix, such as "300ms", "-1.5h" or "2h45m". Valid time units are "ns", "us" (or "µs"), "ms", "s", "m", "h".
  conn_max_lifetime: 5m
  # The maximum amount of time a connection may be idle. Expired connections may be closed lazily before reuse. If it <= 0, connections are not closed due to a connection's idle time.
  # The value is a duration string. A duration string is a possibly signed sequence of decimal numbers, each with optional fraction and a unit suffix, such as "300ms", "-1.5h" or "2h45m". Valid time units are "ns", "us" (or "µs"), "ms", "s", "m", "h".
  conn_max_idle_time: 0

# The default data volume
data_volume: /data

# Harbor Storage settings by default is using /data dir on local filesystem
# Uncomment storage_service setting If you want to using external storage
# storage_service:
#   # ca_bundle is the path to the custom root ca certificate, which will be injected into the truststore
#   # of registry's containers.  This is usually needed when the user hosts a internal storage with self signed certificate.
#   ca_bundle:

#   # storage backend, default is filesystem, options include filesystem, azure, gcs, s3, swift and oss
#   # for more info about this configuration please refer https://distribution.github.io/distribution/about/configuration/
#   # and https://distribution.github.io/distribution/storage-drivers/
#   filesystem:
#     maxthreads: 100
#   # set disable to true when you want to disable registry redirect
#   redirect:
#     disable: false

# Trivy configuration
#
# Trivy DB contains vulnerability information from NVD, Red Hat, and many other upstream vulnerability databases.
# It is downloaded by Trivy from the GitHub release page https://github.com/aquasecurity/trivy-db/releases and cached
# in the local file system. In addition, the database contains the update timestamp so Trivy can detect whether it
# should download a newer version from the Internet or use the cached one. Currently, the database is updated every
# 12 hours and published as a new release to GitHub.
trivy:
  # ignoreUnfixed The flag to display only fixed vulnerabilities
  ignore_unfixed: false
  # skipUpdate The flag to enable or disable Trivy DB downloads from GitHub
  #
  # You might want to enable this flag in test or CI/CD environments to avoid GitHub rate limiting issues.
  # If the flag is enabled you have to download the trivy-offline.tar.gz archive manually, extract trivy.db and
  # metadata.json files and mount them in the /home/scanner/.cache/trivy/db path.
  skip_update: false
  #
  # skipJavaDBUpdate If the flag is enabled you have to manually download the trivy-java.db file and mount it in the
  # /home/scanner/.cache/trivy/java-db/trivy-java.db path
  skip_java_db_update: false
  #
  # The offline_scan option prevents Trivy from sending API requests to identify dependencies.
  # Scanning JAR files and pom.xml may require Internet access for better detection, but this option tries to avoid it.
  # For example, the offline mode will not try to resolve transitive dependencies in pom.xml when the dependency doesn't
  # exist in the local repositories. It means a number of detected vulnerabilities might be fewer in offline mode.
  # It would work if all the dependencies are in local.
  # This option doesn't affect DB download. You need to specify "skip-update" as well as "offline-scan" in an air-gapped environment.
  offline_scan: false
  #
  # Comma-separated list of what security issues to detect. Possible values are vuln, config and secret. Defaults to vuln.
  security_check: vuln
  #
  # insecure The flag to skip verifying registry certificate
  insecure: false
  #
  # timeout The duration to wait for scan completion.
  # There is upper bound of 30 minutes defined in scan job. So if this timeout is larger than 30m0s, it will also timeout at 30m0s.
  timeout: 5m0s
  #
  # github_token The GitHub access token to download Trivy DB
  #
  # Anonymous downloads from GitHub are subject to the limit of 60 requests per hour. Normally such rate limit is enough
  # for production operations. If, for any reason, it's not enough, you could increase the rate limit to 5000
  # requests per hour by specifying the GitHub access token. For more details on GitHub rate limiting please consult
  # https://docs.github.com/rest/overview/resources-in-the-rest-api#rate-limiting
  #
  # You can create a GitHub token by following the instructions in
  # https://help.github.com/en/github/authenticating-to-github/creating-a-personal-access-token-for-the-command-line
  #
  # github_token: xxx

jobservice:
  # Maximum number of job workers in job service
  max_job_workers: 10
  # The jobLoggers backend name, only support "STD_OUTPUT", "FILE" and/or "DB"
  job_loggers:
    - STD_OUTPUT
    - FILE
    # - DB
  # The jobLogger sweeper duration (ignored if jobLogger is stdout)
  logger_sweeper_duration: 1 #days

notification:
  # Maximum retry count for webhook job
  webhook_job_max_retry: 3
  # HTTP client timeout for webhook job
  webhook_job_http_client_timeout: 3 #seconds

# Log configurations
log:
  # options are debug, info, warning, error, fatal
  level: info
  # configs for logs in local storage
  local:
    # Log files are rotated log_rotate_count times before being removed. If count is 0, old versions are removed rather than rotated.
    rotate_count: 50
    # Log files are rotated only if they grow bigger than log_rotate_size bytes. If size is followed by k, the size is assumed to be in kilobytes.
    # If the M is used, the size is in megabytes, and if G is used, the size is in gigabytes. So size 100, size 100k, size 100M and size 100G
    # are all valid.
    rotate_size: 200M
    # The directory on your host that store log
    location: /var/log/harbor

  # Uncomment following lines to enable external syslog endpoint.
  # external_endpoint:
  #   # protocol used to transmit log to external endpoint, options is tcp or udp
  #   protocol: tcp
  #   # The host of external endpoint
  #   host: localhost
  #   # Port of external endpoint
  #   port: 5140

#This attribute is for migrator to detect the version of the .cfg file, DO NOT MODIFY!
_version: 2.12.0

# Uncomment external_database if using external database.
# external_database:
#   harbor:
#     host: harbor_db_host
#     port: harbor_db_port
#     db_name: harbor_db_name
#     username: harbor_db_username
#     password: harbor_db_password
#     ssl_mode: disable
#     max_idle_conns: 2
#     max_open_conns: 0

# Uncomment redis if need to customize redis db
# redis:
#   # db_index 0 is for core, it's unchangeable
#   # registry_db_index: 1
#   # jobservice_db_index: 2
#   # trivy_db_index: 5
#   # it's optional, the db for harbor business misc, by default is 0, uncomment it if you want to change it.
#   # harbor_db_index: 6
#   # it's optional, the db for harbor cache layer, by default is 0, uncomment it if you want to change it.
#   # cache_layer_db_index: 7

# Uncomment external_redis if using external Redis server
# external_redis:
#   # support redis, redis+sentinel
#   # host for redis: <host_redis>:<port_redis>
#   # host for redis+sentinel:
#   #  <host_sentinel1>:<port_sentinel1>,<host_sentinel2>:<port_sentinel2>,<host_sentinel3>:<port_sentinel3>
#   host: redis:6379
#   password:
#   # Redis AUTH command was extended in Redis 6, it is possible to use it in the two-arguments AUTH <username> <password> form.
#   # there's a known issue when using external redis username ref:https://github.com/goharbor/harbor/issues/18892
#   # if you care about the image pull/push performance, please refer to this https://github.com/goharbor/harbor/wiki/Harbor-FAQs#external-redis-username-password-usage
#   # username:
#   # sentinel_master_set must be set to support redis+sentinel
#   #sentinel_master_set:
#   # db_index 0 is for core, it's unchangeable
#   registry_db_index: 1
#   jobservice_db_index: 2
#   trivy_db_index: 5
#   idle_timeout_seconds: 30
#   # it's optional, the db for harbor business misc, by default is 0, uncomment it if you want to change it.
#   # harbor_db_index: 6
#   # it's optional, the db for harbor cache layer, by default is 0, uncomment it if you want to change it.
#   # cache_layer_db_index: 7

# Uncomment uaa for trusting the certificate of uaa instance that is hosted via self-signed cert.
# uaa:
#   ca_file: /path/to/ca

# Global proxy
# Config http proxy for components, e.g. http://my.proxy.com:3128
# Components doesn't need to connect to each others via http proxy.
# Remove component from components array if want disable proxy
# for it. If you want use proxy for replication, MUST enable proxy
# for core and jobservice, and set http_proxy and https_proxy.
# Add domain to the no_proxy field, when you want disable proxy
# for some special registry.
proxy:
  http_proxy:
  https_proxy:
  no_proxy:
  components:
    - core
    - jobservice
    - trivy

# metric:
#   enabled: false
#   port: 9090
#   path: /metrics

# Trace related config
# only can enable one trace provider(jaeger or otel) at the same time,
# and when using jaeger as provider, can only enable it with agent mode or collector mode.
# if using jaeger collector mode, uncomment endpoint and uncomment username, password if needed
# if using jaeger agetn mode uncomment agent_host and agent_port
# trace:
#   enabled: true
#   # set sample_rate to 1 if you wanna sampling 100% of trace data; set 0.5 if you wanna sampling 50% of trace data, and so forth
#   sample_rate: 1
#   # # namespace used to differentiate different harbor services
#   # namespace:
#   # # attributes is a key value dict contains user defined attributes used to initialize trace provider
#   # attributes:
#   #   application: harbor
#   # # jaeger should be 1.26 or newer.
#   # jaeger:
#   #   endpoint: http://hostname:14268/api/traces
#   #   username:
#   #   password:
#   #   agent_host: hostname
#   #   # export trace data by jaeger.thrift in compact mode
#   #   agent_port: 6831
#   # otel:
#   #   endpoint: hostname:4318
#   #   url_path: /v1/traces
#   #   compression: false
#   #   insecure: true
#   #   # timeout is in seconds
#   #   timeout: 10

# Enable purge _upload directories
upload_purging:
  enabled: true
  # remove files in _upload directories which exist for a period of time, default is one week.
  age: 168h
  # the interval of the purge operations
  interval: 24h
  dryrun: false

# Cache layer configurations
# If this feature enabled, harbor will cache the resource
# project/project_metadata/repository/artifact/manifest in the redis
# which can especially help to improve the performance of high concurrent
# manifest pulling.
# NOTICE
# If you are deploying Harbor in HA mode, make sure that all the harbor
# instances have the same behaviour, all with caching enabled or disabled,
# otherwise it can lead to potential data inconsistency.
cache:
  # not enabled by default
  enabled: false
  # keep cache for one day by default
  expire_hours: 24

# Harbor core configurations
# Uncomment to enable the following harbor core related configuration items.
# core:
#   # The provider for updating project quota(usage), there are 2 options, redis or db,
#   # by default is implemented by db but you can switch the updation via redis which
#   # can improve the performance of high concurrent pushing to the same project,
#   # and reduce the database connections spike and occupies.
#   # By redis will bring up some delay for quota usage updation for display, so only
#   # suggest switch provider to redis if you were ran into the db connections spike around
#   # the scenario of high concurrent pushing to same project, no improvement for other scenes.
#   quota_update_provider: redis # Or db
EOF

  # harbor.yml carries the admin and database passwords - keep it root-only
  chmod 600 /opt/harbor/harbor.yml
}

# --- Main Menu function --- #

function help {
  echo "Usage: $0 [parameter]"
  echo ""
  echo "[Parameters]            | [Description]"
  echo "help                    | Display this help message"
  echo "install-harbor          | Installs Harbor registry"
  echo "uninstall-harbor        | Uninstalls Harbor registry"
  echo "offline-prep            | Prepares an offline package"
  echo "update-certificates     | Updates Harbor TLS certificates (self-signed or user-supplied)"
}

# When sourced (e.g. by a test harness), stop here without running the CLI wrapper
if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then
  return 0
fi

# Start CLI Wrapper
while [[ $# -gt 0 ]]; do
  case "$1" in
    help)
      help
      exit 0
      ;;
    install-harbor)
      check_root_privileges
      os_type
      select_docker_packages
      preflight_checks install
      echo "###   Harbor Installation Started - $(date)  ###"
      install_harbor
      echo "###   Harbor Installation Finished - $(date)  ###"
      exit 0
      ;;
    uninstall-harbor)
      check_root_privileges
      echo "###   Harbor Uninstallation Started - $(date)   ###"
      uninstall_harbor
      exit 0
      ;;
    offline-prep)
      check_root_privileges
      os_type
      select_docker_packages
      preflight_checks offline-prep
      echo "###   Harbor Offline Preparation Started - $(date)   ###"
      harbor_offline_prep
      echo "###   Harbor Offline Preparation Finished - $(date)   ###"
      exit 0
      ;;
    update-certificates)
      check_root_privileges
      os_type
      preflight_checks update-certificates
      echo "###   Update Certificates Started - $(date)  ###"
      update_certificates
      echo "###   Update Certificates Finished - $(date)  ###"
      exit 0
      ;;

    *)
      echo "Invalid option: $1"
      help
      exit 1
      ;;
  esac
  shift
done

help
# End CLI Wrapper
