#!/bin/bash

# This script contains functions for installing a Harbor registry on Ubuntu for storing container images

SCRIPT_VERSION="1.2.0"

# Record which variables the caller explicitly set BEFORE defaults are applied, so
# recorded install-time values from .install-env can fill in unset variables without
# ever overriding an explicit user choice (precedence: env > .install-env > default).
# Empty counts as not set, which matches the :- defaults below.
user_set_registry_common_name=${REGISTRY_COMMON_NAME:+x}
user_set_harbor_port=${HARBOR_PORT:+x}
user_set_harbor_version=${HARBOR_VERSION:+x}
user_set_harbor_password=${HARBOR_PASSWORD:+x}
user_set_harbor_db_password=${HARBOR_DB_PASSWORD:+x}

# --- User Defined Variables --- #
DEBUG=${DEBUG:-1}

# Harbor configuration
HARBOR_VERSION=${HARBOR_VERSION:-2.15.0}
HARBOR_PORT=${HARBOR_PORT:-443}
# A name other than admin becomes a second system administrator, because Harbor can't rename admin
HARBOR_USERNAME=${HARBOR_USERNAME:-admin}
HARBOR_USER_EMAIL=${HARBOR_USER_EMAIL:-""}
HARBOR_PASSWORD=${HARBOR_PASSWORD:-Harbor12345}
HARBOR_DB_PASSWORD=${HARBOR_DB_PASSWORD:-root123}
DOCKER_BRIDGE_CIDR=${DOCKER_BRIDGE_CIDR:-"172.30.0.1/16"}
PROJECTS=${PROJECTS:-""}
# How long to wait for the Harbor API after (re)starting it
HARBOR_API_WAIT_SEC=${HARBOR_API_WAIT_SEC:-60}
# true = run the full install even when nothing has changed
HARBOR_FORCE_REDEPLOY=${HARBOR_FORCE_REDEPLOY:-false}
# true = ignore a harbor-install-files/VERSION.txt left by offline-prep, and stay online
HARBOR_FORCE_ONLINE=${HARBOR_FORCE_ONLINE:-false}
HARBOR_ALLOW_DOWNGRADE=${HARBOR_ALLOW_DOWNGRADE:-false}
# A version change dumps Harbor's database first, to /data/backup/harbor-installer. false skips the dump.
HARBOR_DB_DUMP=${HARBOR_DB_DUMP:-true}
# After a successful version change, remove the goharbor/* images of other versions. false keeps them.
HARBOR_REMOVE_OLD_IMAGES=${HARBOR_REMOVE_OLD_IMAGES:-true}
# Optional Docker version, used when Docker isn't installed yet. The start of a version is enough.
DOCKER_VERSION=${DOCKER_VERSION:-""}
# Which install_packages.sh to fetch: a tag, branch or commit. The URL wins over the ref, and the checksum is optional.
INSTALL_PACKAGES_REF=${INSTALL_PACKAGES_REF:-"v1.1.3"}
INSTALL_PACKAGES_URL=${INSTALL_PACKAGES_URL:-"https://raw.githubusercontent.com/Chubtoad5/install-packages/${INSTALL_PACKAGES_REF}/install_packages.sh"}
INSTALL_PACKAGES_SHA256=${INSTALL_PACKAGES_SHA256:-""}
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
# Lifetime of a CA this installer makes: a first install, or ROTATE_CA. Unset, it's DURATION_DAYS. An existing CA keeps its own.
CA_DURATION_DAYS=${CA_DURATION_DAYS:-$DURATION_DAYS}
# Replace the CA. Every client must then trust the new one, so this never happens by itself.
ROTATE_CA=${ROTATE_CA:-false}
CA_EXPIRY_WARN_DAYS=${CA_EXPIRY_WARN_DAYS:-30}
# Who a recipient of an air-gap bundle asks for source code, in LICENSES/WRITTEN_OFFER.txt.
LICENSE_OFFER_CONTACT=${LICENSE_OFFER_CONTACT:-"the Chubtoad5 project via https://github.com/Chubtoad5"}
# On a re-run, keep a server certificate with more than this many days left
CERT_RENEW_BEFORE_DAYS=${CERT_RENEW_BEFORE_DAYS:-30}

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
user_name=${SUDO_USER:-$(whoami)}
current_hostname=$(hostname)
certs_dir="/opt/harbor/certs"
install_env_file="/opt/harbor/.install-env"
docker_certs_root="/etc/docker/certs.d"
data_dir="/data"
db_dump_dir="$data_dir/backup/harbor-installer"
# The Harbor version running before this run, when data already existed: set by install_harbor
previous_version=""
data_preexisting=0
recorded_install_files_dir=""
recorded_docker_users=""
docker_was_active=0
bridge_changed=0

#### --- Functions --- ###

# --- Menu Functions --- #

function install_harbor {
  # Called directly rather than through run_step: at DEBUG=0 it would hide why the run stopped
  check_passwords || exit 1
  check_durations || exit 1
  check_harbor_username || exit 1
  if [[ -d "$data_dir/database" ]]; then
    data_preexisting=1
    previous_version=$(running_harbor_version)
    echo "  NOTE: Existing Harbor data found in $data_dir."
    echo "  HARBOR_PASSWORD is only applied on the very first install - the admin"
    echo "  password already stored in $data_dir remains in effect for this install."
    echo "  Run 'uninstall-harbor' first if you need a clean install with a new password."
    check_existing_db_password || exit 1
    preserve_existing_yml_passwords
    check_downgrade || exit 1
  fi
  check_existing_ca || exit 1
  if harbor_unchanged; then
    echo "  No change: Harbor is running as requested. Skipping Docker, certificates and redeploy."
    echo "  (HARBOR_FORCE_REDEPLOY=true runs the full install anyway.)"
    run_step create_harbor_service
    run_step create_harbor_projects
  else
    # Fetch first, so a bad version fails before anything has changed
    run_step prefetch_harbor_installer
    # Called directly: at DEBUG=0 run_step would hide why the run stopped, or where the dump went
    dump_database_before_upgrade || exit 1
    run_step write_install_env
    run_step install_docker_utility
    run_step cert_gen
    run_step harbor_cert_install
    run_step gen_harbor_yml
    run_step run_harbor_installer
    run_step create_harbor_service
    run_step create_harbor_projects
    run_step commit_install_version
    remove_old_images
  fi
  echo "# ---  Harbor Install Completed! --- #"
  echo "  Harbor install and compose files are in /opt/harbor and /data directories"
  echo "  Harbor Version: $HARBOR_VERSION"
  echo "  URL: https://$mgmt_ip:$HARBOR_PORT"
  echo "  FQDN URL: https://$REGISTRY_COMMON_NAME:$HARBOR_PORT"
  if [[ "$HARBOR_USERNAME" == "admin" ]]; then
    echo "  Username: admin"
  else
    echo "  Administrator: $HARBOR_USERNAME"
    echo "  The built-in admin account also exists, with the same password. Change it in the UI if you don't want that."
  fi
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
  # Remove the docker group membership only for users this installer added
  local group_user
  for group_user in $recorded_docker_users; do
    if id -nG "$group_user" 2>/dev/null | tr ' ' '\n' | grep -qx docker; then
      gpasswd -d "$group_user" docker > /dev/null 2>&1 || true
      echo "  Removed $group_user from the docker group (membership was added by the installer)"
    fi
  done
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
  local harbor_subdirs=(ca_download database job_logs redis registry secret trivy-adapter chart_storage backup/harbor-installer)
  local sub
  for sub in "${harbor_subdirs[@]}"; do
    [[ -e "$data_dir/$sub" ]] && rm -rf "${data_dir:?}/$sub"
  done
  # Only when empty: another tool's backups may share it
  rmdir "$data_dir/backup" 2>/dev/null || true
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
  check_passwords || exit 1
  preserve_existing_yml_passwords
  # A user-supplied CA replaces this one, and is a way out of an expired one, so only self-signed renewals check it
  if [[ "$NEW_CERT_GEN" -eq 1 ]]; then
    check_durations || exit 1
    check_existing_ca || exit 1
  fi
  # Anything from here on can be rolled back, and the snapshot has to come first:
  # new_cert_check already overwrites the certificate files
  run_step snapshot_for_cert_update
  # Validate + stage the new cert material BEFORE stopping anything: a bad
  # user-supplied chain (or failed generation) must abort with the running
  # stack untouched, not leave the registry down
  run_step new_cert_check
  echo "  Stopping Harbor containers..."
  if [[ -f /etc/systemd/system/harbor-docker.service ]]; then
    systemctl stop harbor-docker.service || true
  fi
  docker compose -f /opt/harbor/docker-compose.yml down || true
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
  discard_cert_snapshot
  # The certificates are right by now, so a slow API is worth a warning rather than a rollback
  wait_for_harbor_api || echo "WARNING: Harbor's API isn't answering yet. Check with: curl -k https://$mgmt_ip:$HARBOR_PORT/api/v2.0/ping"
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
      # Every mode needs curl: online to fetch, and all of them for the API check at the end.
      # A bundle can bring its own, but an older bundle can't.
      if ! bundle_mode || ! bundle_has_curl; then
        required_cmds+=(curl)
      fi
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
    # Optional pin, in install_packages.sh's name=version form. It's for a new install or a bundle: a Docker that's
    # already here is never moved, the same rule as image_pull_push.sh.
    local i pkg
    [[ -n "$DOCKER_VERSION" ]] || return 0
    if [[ "${1:-}" != "save" ]] && command -v docker >/dev/null 2>&1; then
      echo "  Note: Docker is already installed, so DOCKER_VERSION=$DOCKER_VERSION is ignored."
      return 0
    fi
    if [[ -n "$DOCKER_VERSION" ]]; then
      for i in "${!DOCKER_PACKAGES[@]}"; do
        pkg=${DOCKER_PACKAGES[$i]}
        case "$pkg" in
          docker-ce|docker-ce-cli|docker) DOCKER_PACKAGES[i]="$pkg=$DOCKER_VERSION" ;;
        esac
      done
    fi
}

# Bundle mode: offline-prep's VERSION.txt is present, and nobody asked to stay online
function bundle_mode () {
  [[ -f "$base_dir/harbor-install-files/VERSION.txt" && "${HARBOR_FORCE_ONLINE,,}" != "true" ]]
}

function bundle_has_curl () {
  local archive="$base_dir/harbor-install-files/apt-packages/offline-packages.tar.gz"
  [[ -f "$archive" ]] && tar -tzf "$archive" 2>/dev/null | grep -qE '/curl[-_][0-9]'
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

# fetch_helper <dest> <url> <ref> [sha256]: a cached copy from another ref, or with no record, is fetched again
function fetch_helper () {
    local dest=$1 url=$2 ref=$3 sha=${4:-} ref_file
    ref_file="$(dirname "$dest")/.$(basename "$dest").ref"
    if [[ -s "$dest" && "$(cat "$ref_file" 2>/dev/null)" == "$ref" ]]; then
        return 0
    fi
    echo "  Downloading $(basename "$dest") ($ref)..."
    if ! curl -fsSL "$url" -o "$dest.tmp"; then
        rm -f "$dest.tmp"
        echo "Error: Failed to download $url"
        return 1
    fi
    if [[ -n "$sha" ]] && ! echo "$sha  $dest.tmp" | sha256sum -c --status; then
        rm -f "$dest.tmp"
        echo "Error: $(basename "$dest") doesn't match its checksum."
        return 1
    fi
    mv "$dest.tmp" "$dest"
    chmod +x "$dest"
    printf '%s\n' "$ref" > "$ref_file"
}

function install_packages_check () {
    local dest="$base_dir/harbor-install-files/apt-packages/install_packages.sh"
    mkdir -p "$base_dir/harbor-install-files/apt-packages"
    # A bundle uses the copy it brought, and an air-gapped run must never reach the download
    if bundle_mode && [[ -s "$dest" ]]; then
        return 0
    fi
    fetch_helper "$dest" "$INSTALL_PACKAGES_URL" "$INSTALL_PACKAGES_REF" "$INSTALL_PACKAGES_SHA256"
}

# On an EL host, the running kernel's kernel-modules-extra when this host's repos still have it, so that the bundle carries
# it. A target built from the same image then gets xt_addrtype with no local media (spec 15, F1). Prints nothing
# elsewhere, and a note on stderr when the repos no longer have it.
function el_modules_extra_pkg () {
    case "$os_id" in
        rhel|centos|rocky|almalinux|fedora) ;;
        *) return 0 ;;
    esac
    local pkg
    pkg="kernel-modules-extra-$(uname -r)"
    if [[ -n "$(dnf -q repoquery --available "$pkg" 2>/dev/null)" ]]; then
        echo "$pkg"
    else
        echo "  Note: $pkg isn't in this host's repos, so the bundle won't carry it. A target that lacks xt_addrtype will need it from local media." >&2
    fi
}

# The kernel-modules-extra package the bundle carries, as kernel-modules-extra-<kernel>, or nothing
function bundled_modules_extra () {
    local archive="$base_dir/harbor-install-files/apt-packages/offline-packages.tar.gz" listing
    [[ -f "$archive" ]] || return 0
    listing=$(tar -tzf "$archive" 2>/dev/null) || return 0
    sed -n 's#^.*/\(kernel-modules-extra-[0-9][^/]*\)\.rpm$#\1#p' <<< "$listing" | tail -n 1
}

function ensure_el_kernel_modules() {
    # EL10 ships the legacy xtables match modules (xt_addrtype et al.) in
    # kernel-modules-extra, which stock Rocky/Alma/RHEL 10 cloud images omit.
    # dockerd cannot create its NAT chains without xt_addrtype and never starts (P4-01)
    case "$os_id" in
        rhel|centos|rocky|almalinux|fedora) ;;
        *) return 0 ;;
    esac
    if modprobe -n xt_addrtype &>/dev/null; then
        return 0
    fi
    local kver bundled
    kver=$(uname -r)
    echo "  Kernel module xt_addrtype is unavailable (the docker daemon requires it)."
    if bundle_mode && [[ -f "$base_dir/harbor-install-files/apt-packages/offline-packages.tar.gz" ]]; then
        # A bundle built on a host running this same kernel carries its kernel-modules-extra (spec 15, F1)
        bundled=$(bundled_modules_extra)
        if [[ "$bundled" != "kernel-modules-extra-$kver" ]]; then
            [[ -n "$bundled" ]] && echo "  The bundle carries $bundled, which is for another kernel: it was built on a host running ${bundled#kernel-modules-extra-}."
            echo "Error: install kernel-modules-extra for the running kernel from local media"
            echo "  (dnf install kernel-modules-extra-$kver), then re-run this script."
            return 1
        fi
        echo "  Installing kernel-modules-extra-$kver from the bundle..."
        if ! (cd "$base_dir/harbor-install-files/apt-packages" && ./install_packages.sh offline "kernel-modules-extra-$kver"); then
            echo "Error: kernel-modules-extra-$kver from the bundle failed to install."
            return 1
        fi
    else
        echo "  Installing kernel-modules-extra-$kver to match the running kernel..."
        if ! dnf install -y "kernel-modules-extra-$kver"; then
            # The running kernel's package has aged out of the repos: install the
            # latest kernel + modules instead, which only take effect after a reboot
            echo "  kernel-modules-extra for the running kernel is no longer available;"
            echo "  installing the latest kernel and kernel-modules-extra..."
            if ! dnf install -y kernel kernel-modules-extra; then
                echo "Error: Failed to install kernel-modules-extra. Docker cannot start without the xt_addrtype module."
                return 1
            fi
            echo "Error: A newer kernel and kernel-modules-extra were installed, but the running kernel"
            echo "  ($kver) still has no xt_addrtype module. Reboot into the new kernel, then re-run this script."
            return 1
        fi
    fi
    if ! modprobe xt_addrtype; then
        echo "Error: xt_addrtype still fails to load after installing kernel-modules-extra-$kver."
        return 1
    fi
    echo "  xt_addrtype kernel module loaded."
}

# A bundled helper may predate these flags, and an old script rejects them
function helper_flags () {
    if ./install_packages.sh --version >/dev/null 2>&1 && command -v docker >/dev/null 2>&1; then
        # Docker is already here: don't move it just because Harbor is being re-run
        echo "--no-upgrade"
    fi
}

function install_docker_utility() {
    install_packages_check || return 1
    systemctl is-active --quiet docker && docker_was_active=1
    create_bridge_json || return 1
    cd "$base_dir/harbor-install-files/apt-packages" || return 1
    local flags=() packages=("${DOCKER_PACKAGES[@]}")
    read -r -a flags <<< "$(helper_flags)"
    if bundle_mode && [[ -f "$base_dir/harbor-install-files/apt-packages/offline-packages.tar.gz" ]]; then
        # Only a host without it. RHEL 9's curl-minimal conflicts with curl, and it's all the install needs.
        if ! command -v curl >/dev/null 2>&1 && bundle_has_curl; then
          packages+=(curl)
        fi
        ./install_packages.sh offline "${flags[@]}" "${packages[@]}" || { cd "$base_dir" || true; return 1; }
    else
        ensure_docker_repo || { cd "$base_dir" || true; return 1; }
        ./install_packages.sh online "${flags[@]}" "${packages[@]}" || { cd "$base_dir" || true; return 1; }
    fi
    cd "$base_dir" || return 1
    require_cmds curl
    if ! command -v docker &> /dev/null; then
        echo "Error: Docker installation failed."
        return 1
    fi
    ensure_el_kernel_modules || return 1
    if ! systemctl enable --now docker; then
        echo "Error: Failed to enable and start the docker service."
        return 1
    fi
    if ! systemctl is-active --quiet docker; then
        echo "Error: The docker service is not active after 'systemctl enable --now docker'."
        return 1
    fi
    # Only a changed daemon.json on a Docker that was already running needs a restart.
    # Docker reads certs.d per connection, so the CA copy never does.
    if [[ $docker_was_active -eq 1 && $bridge_changed -eq 1 ]]; then
        echo "  daemon.json changed: restarting Docker"
        systemctl restart docker || { echo "Error: Failed to restart docker."; return 1; }
    fi
    # Record who this installer added to the docker group, so uninstall removes only those
    if id -nG "$user_name" 2>/dev/null | tr ' ' '\n' | grep -qx docker; then
        echo "  User $user_name is already in the docker group"
    else
        usermod -aG docker "$user_name"
        record_docker_group_user "$user_name"
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
      bridge_changed=1
      echo "  Merged bip: $DOCKER_BRIDGE_CIDR into existing /etc/docker/daemon.json"
  else
      cat <<EOF | tee /etc/docker/daemon.json > /dev/null
{
  "bip": "$DOCKER_BRIDGE_CIDR"
}
EOF
      bridge_changed=1
      echo "  Created /etc/docker/daemon.json with bip: $DOCKER_BRIDGE_CIDR"
  fi
}

# Whole days until a certificate expires. Negative once it has.
function cert_days_left () {
  local end
  end=$(openssl x509 -noout -enddate -in "$1" 2>/dev/null | cut -d= -f2) || return 1
  echo $(( ($(date -d "$end" +%s) - $(date +%s)) / 86400 ))
}

# An expired CA signs certificates no client will accept, so it stops the run, before anything changes.
# Replacing it breaks every client's trust, so that only ever happens on request.
ca_rotation_due=0

function check_existing_ca () {
  local ca="$certs_dir/ca.crt" left
  if [[ "${ROTATE_CA,,}" == "true" && -s "$ca" ]]; then
    ca_rotation_due=1
    echo "  ROTATE_CA=true: the CA will be replaced."
    echo "  Every client must trust the new one: /data/ca_download/ca.crt"
    return 0
  fi
  [[ -s "$ca" ]] || return 0
  left=$(cert_days_left "$ca") || { echo "Error: can't read $ca."; return 1; }
  if ! openssl x509 -checkend 0 -noout -in "$ca" >/dev/null 2>&1; then
    echo "Error: the CA in $certs_dir has expired (${left#-} days ago). Nothing has been changed."
    echo "  ROTATE_CA=true generates a new CA. Every client must then trust it again."
    return 1
  fi
  if (( left < CA_EXPIRY_WARN_DAYS )); then
    echo "  WARNING: the CA in $certs_dir expires in $left days. ROTATE_CA=true replaces it, and clients must then trust the new one."
  fi
}

# Called once everything that can fail early has passed, and after update-certificates has taken its snapshot.
# Moving the CA any sooner, a failed run would come back with no CA, and the next one would silently make a new one.
function rotate_ca_if_due () {
  [[ "$ca_rotation_due" -eq 1 && -s "$certs_dir/ca.crt" ]] || return 0
  local stamp
  stamp=$(date -u +%Y%m%d%H%M%S)
  mv "$certs_dir/ca.crt" "$certs_dir/ca.crt.old-$stamp" || return 1
  mv "$certs_dir/ca.key" "$certs_dir/ca.key.old-$stamp" 2>/dev/null
  ca_rotation_due=0
  echo "  Moved the old CA aside (.old-$stamp). A new CA will be generated."
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
  echo "  Generating a new certificate authority (valid $CA_DURATION_DAYS days)..."
  mkdir -p "$certs_dir"
  # Generate CA key
  openssl genrsa -out "$certs_dir/ca.key" 4096 || return 1
  # Generate CA certificate
  openssl req -x509 -new -nodes -sha512 -days "$CA_DURATION_DAYS" -subj "/C=$COUNTRY/ST=$STATE/L=$LOCATION/O=$ORGANIZATION/CN=$REGISTRY_COMMON_NAME" -key "$certs_dir/ca.key" -out "$certs_dir/ca.crt" || return 1
}

# server_cert_reusable: is the existing key and certificate still right for this install?
function server_cert_reusable () {
  local crt="$certs_dir/$REGISTRY_COMMON_NAME.crt" key="$certs_dir/$REGISTRY_COMMON_NAME.key" san subject
  [[ -s "$crt" && -s "$key" && -s "$certs_dir/$REGISTRY_COMMON_NAME-fullchain.crt" && -s "$certs_dir/ca.crt" ]] || return 1
  openssl verify -CAfile "$certs_dir/ca.crt" "$crt" >/dev/null 2>&1 || return 1
  openssl x509 -checkend $((CERT_RENEW_BEFORE_DAYS * 86400)) -noout -in "$crt" >/dev/null 2>&1 || return 1
  san=$(openssl x509 -noout -ext subjectAltName -in "$crt" 2>/dev/null)
  grep -qF "DNS:$REGISTRY_COMMON_NAME" <<< "$san" || return 1
  grep -qF "DNS:$current_hostname" <<< "$san" || return 1
  grep -qF "IP Address:$mgmt_ip" <<< "$san" || return 1
  subject=$(openssl x509 -noout -subject -nameopt compat -in "$crt" 2>/dev/null)
  [[ "$subject" == "subject=/C=$COUNTRY/ST=$STATE/L=$LOCATION/O=$ORGANIZATION/CN=$REGISTRY_COMMON_NAME" ]] || return 1
}

function server_cert_gen () {
  # A leaf can't usefully outlive its CA, so limit it to what the CA has left
  local days=$DURATION_DAYS left
  left=$(cert_days_left "$certs_dir/ca.crt") || return 1
  if (( days > left )); then
    (( left + 1 < DURATION_DAYS )) && echo "  WARNING: DURATION_DAYS=$DURATION_DAYS, but the CA only has $left days left. Issuing for $left days."
    days=$left
  fi
  echo "  Creating server certificate valid for $days days (signed by the CA in $certs_dir)..."
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
  openssl x509 -req -sha512 -days "$days" -extfile "$certs_dir/v3.ext" -CA "$certs_dir/ca.crt" -CAkey "$certs_dir/ca.key" -CAcreateserial -in "$certs_dir/$REGISTRY_COMMON_NAME.csr" -out "$certs_dir/$REGISTRY_COMMON_NAME.crt" || return 1
  # Convert signed certificate from .crt to .cert
  openssl x509 -inform PEM -in "$certs_dir/$REGISTRY_COMMON_NAME.crt" -out "$certs_dir/$REGISTRY_COMMON_NAME.cert" || return 1
  # Create fullchain (server cert + CA cert) so nginx sends the complete chain during TLS handshake
  cat "$certs_dir/$REGISTRY_COMMON_NAME.crt" "$certs_dir/ca.crt" > "$certs_dir/$REGISTRY_COMMON_NAME-fullchain.crt"
  echo "Certificate generation completed..."
}

# Install path: keep a server certificate that's still good, so a redeploy doesn't change the key
function cert_gen () {
  rotate_ca_if_due || return 1
  ca_gen || return 1
  if server_cert_reusable; then
    echo "  Keeping the existing server certificate: still valid, and right for this name and address."
    return 0
  fi
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
}

# Have the installer in hand before anything changes
function prefetch_harbor_installer() {
  local installer_tgz="$base_dir/harbor-install-files/harbor-offline-installer-v$HARBOR_VERSION.tgz"
  mkdir -p "$base_dir/harbor-install-files"
  if bundle_mode; then
    if [[ ! -s "$installer_tgz" ]]; then
      echo "Error: $installer_tgz is missing or empty in this offline bundle."
      echo "  If this machine isn't air-gapped and the bundle is left over from offline-prep, set HARBOR_FORCE_ONLINE=true."
      return 1
    fi
  else
    download_harbor_offline_package || return 1
  fi
}

function run_harbor_installer() {
  local installer_tgz="$base_dir/harbor-install-files/harbor-offline-installer-v$HARBOR_VERSION.tgz"
  # An upgrade finds the old version's image archive here. Upstream's install.sh tests 'harbor*.tar.gz', which can't
  # take two files, so it would skip loading the images: they'd come from Docker Hub, or in an air gap, not at all.
  rm -f /opt/harbor/harbor.v*.tar.gz
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
  # curl goes in too: the install needs it for the API check, and minimal images don't have it. On EL, the running
  # kernel's kernel-modules-extra too (spec 15, F1).
  local extra
  extra=$(el_modules_extra_pkg)
  if ! ./install_packages.sh save "${DOCKER_PACKAGES[@]}" curl ${extra:+"$extra"}; then
    echo "Error: install_packages.sh failed to save the docker packages (${DOCKER_PACKAGES[*]}${extra:+ $extra})."
    cd "$base_dir" || return 1
    return 1
  fi
  # Verify a usable package archive was actually produced - the offline package
  # contract includes offline-packages.tar.gz
  if [[ ! -s offline-packages.tar.gz ]] || ! tar -tzf offline-packages.tar.gz 2>/dev/null | grep -qE '\.(deb|rpm)$'; then
    echo "Error: offline-packages.tar.gz was not produced or contains no .deb/.rpm packages."
    cd "$base_dir" || return 1
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
  # Write a LICENSES/ third-party manifest and a written offer into the offline archive. Harbor and
  # its components are Apache-2.0, and the offline tgz ships several images under their own licenses
  # (notably Redis, whose license is version-dependent). The OS packages include GPL and LGPL ones:
  # Docker needs iptables, and curl needs GnuTLS, librtmp and libidn2. So they get a written offer.
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

Each image's own license/notice ships inside the image. The installer scripts are
Apache-2.0 (Chubtoad5).

OS packages in harbor-install-files/apt-packages/offline-packages.tar.gz: Docker CE
and containerd (Apache-2.0), curl, and whatever they depend on for this OS. Most packages
carry their own license (on Debian and Ubuntu, /usr/share/doc/<package>/copyright once
installed; on RHEL and SLES, rpm -q --licensefiles <package>). Docker's own packages may
not: its source and license are at https://github.com/moby/moby.

Some of them are copyleft. On Ubuntu, that includes iptables (GPL-2.0-or-later), GnuTLS
and librtmp (LGPL), and libidn2 (LGPL or GPL). On RHEL-family hosts, the bundle may also carry
the build host's kernel-modules-extra, part of the Linux kernel (GPL-2.0), when its repos had
it (see the list below). Other systems differ. They are covered by WRITTEN_OFFER.txt.

The packages in this bundle:
$(tar -tzf "$base_dir/harbor-install-files/apt-packages/offline-packages.tar.gz" 2>/dev/null | grep -E '\.(deb|rpm)$' | sed 's|.*/||' | sort)
EOF
  cat > "$dir/WRITTEN_OFFER.txt" <<EOF
WRITTEN OFFER FOR CORRESPONDING SOURCE CODE (GPL, LGPL)

This air-gap bundle redistributes operating system packages in binary form, in
harbor-install-files/apt-packages/offline-packages.tar.gz. THIRD_PARTY_NOTICES.txt lists
them. Some are licensed under the GNU General Public License or the GNU Lesser General
Public License.

The distributor of this bundle hereby makes a written offer, valid for three (3) years
from the date this bundle was created ($(date +%Y-%m-%d)), to give any third party who
possesses this bundle a complete machine-readable copy of the corresponding source code
for those packages, for a charge no more than the cost of physically performing the
source distribution.

The source is also publicly available from the operating system distribution that each
package came from (for example, apt-get source <package> on Debian and Ubuntu).

To request the source on a physical medium, contact: ${LICENSE_OFFER_CONTACT}

This offer is extended by whoever distributes this bundle, and is independent of the
Apache-2.0 license that covers the installer scripts themselves.
EOF
  echo "  Wrote LICENSES/ (third-party manifest + written offer for the OS packages)."
}

function prepare_offline_package() {
  echo "  Generating offline archive..."
  cd "$base_dir" || return 1
  echo "Offline package generated on $(date) for $os_release_version, Harbor version $HARBOR_VERSION, installer version $SCRIPT_VERSION" | tee "$base_dir/harbor-install-files/VERSION.txt"
  generate_bundle_licenses
  tar czvf harbor-offline-package.tar.gz harbor-install-files/ install_harbor.sh LICENSES || return 1
}

# --- Update Certificate Functions --- #

function new_cert_check() {
  if [[ "$NEW_CERT_GEN" -eq 1 ]]; then
    echo "  Generating new self-signed certificate (existing CA is reused when present)..."
    rotate_ca_if_due || return 1
    ca_gen || return 1
    server_cert_gen || return 1
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

# Escape for a double-quoted YAML scalar, a quoted curl config value or a JSON string.
# All three use these same two escapes, and check_passwords rejects control characters.
function dq_escape () {
  local s=$1
  s=${s//\\/\\\\}
  s=${s//\"/\\\"}
  printf '%s' "$s"
}

function dq_unescape () {
  local s=$1
  s=${s//\\\"/\"}
  s=${s//\\\\/\\}
  printf '%s' "$s"
}

# yml_password <admin|db> [file]: what harbor.yml holds. Handles quoted lines, and the unquoted ones older installs wrote.
function yml_password () {
  local which=$1 file=${2:-/opt/harbor/harbor.yml} line
  if [[ "$which" == admin ]]; then
    line=$(sed -n 's/^harbor_admin_password: *//p' "$file" | head -n 1)
  else
    line=$(sed -n '/^database:/,/^[^ #]/{s/^  password: *//p}' "$file" | head -n 1)
  fi
  if [[ "$line" == \"*\" ]]; then
    line=${line#\"}
    line=${line%\"}
    dq_unescape "$line"
  else
    printf '%s' "$line"
  fi
}

# running_harbor_version: from the containers, or else the record. Empty when neither says.
function running_harbor_version () {
  local image
  image=$(docker inspect -f '{{.Config.Image}}' harbor-core 2>/dev/null || true)
  if [[ "$image" == *:v* ]]; then
    echo "${image##*:v}"
  elif [[ -f "$install_env_file" ]]; then
    sed -n 's/^HARBOR_VERSION=//p' "$install_env_file"
  fi
}

# Harbor's database schema only moves forward: an older Harbor can't start on it, so its API never comes back.
function check_downgrade () {
  local current
  [[ "$HARBOR_ALLOW_DOWNGRADE" == "true" ]] && return 0
  current=$(running_harbor_version)
  [[ -n "$current" && "$current" != "$HARBOR_VERSION" ]] || return 0
  if [[ "$(printf '%s\n%s\n' "$current" "$HARBOR_VERSION" | sort -V | head -1)" == "$HARBOR_VERSION" ]]; then
    echo "Error: Harbor $current is installed, and HARBOR_VERSION=$HARBOR_VERSION is older."
    echo "  An older Harbor can't start on a newer database, so this would leave it down."
    echo "  To go back, restore a backup of $data_dir. HARBOR_ALLOW_DOWNGRADE=true skips this check."
    return 1
  fi
}

function preserve_existing_yml_passwords () {
  # A re-run regenerates harbor.yml - keep the passwords the running
  # install uses unless the caller explicitly re-passed them
  [[ -f /opt/harbor/harbor.yml ]] || return 0
  local current
  if [[ -z "$user_set_harbor_password" ]]; then
    current=$(yml_password admin)
    [[ -n "$current" ]] && HARBOR_PASSWORD="$current"
  fi
  if [[ -z "$user_set_harbor_db_password" ]]; then
    current=$(yml_password db)
    [[ -n "$current" ]] && HARBOR_DB_PASSWORD="$current"
  fi
}

# Postgres keeps the password it was created with, so writing a different one to harbor.yml only breaks Harbor
function check_existing_db_password () {
  if [[ -f /opt/harbor/harbor.yml ]]; then
    [[ -n "$user_set_harbor_db_password" ]] || return 0
    if [[ "$(yml_password db)" != "$HARBOR_DB_PASSWORD" ]]; then
      echo "Error: HARBOR_DB_PASSWORD differs from the password this install's database was created with."
      echo "  It only takes effect on a first install, so nothing has been changed."
      echo "  Run again without it, or change the database password by hand."
      return 1
    fi
  elif [[ -z "$user_set_harbor_db_password" ]]; then
    echo "Error: $data_dir/database exists, but /opt/harbor/harbor.yml is gone, so the database password is unknown."
    echo "  Writing the wrong one would break Harbor. Pass the password it was created with as HARBOR_DB_PASSWORD."
    echo "  If nobody chose one when it was first installed, that's the default: HARBOR_DB_PASSWORD=root123"
    return 1
  fi
}

# compose_changes <value>: what docker compose would change in this value, read from an env file as Harbor's are (H16).
# Prints the first reason and returns 0, or returns 1 when compose reads it back unchanged. Measured on compose v5.6.1:
# it expands $name, ${name} and $$, cuts at a # after a space, trims both ends, and reads a leading quote as quoting.
function compose_changes () {
  local v=$1 dollar='[$][A-Za-z_{$]'
  if [[ "$v" =~ $dollar ]]; then
    echo 'a $ before a letter, _, { or $'
  elif [[ "$v" == *" #"* ]]; then
    echo 'a # after a space'
  elif [[ "$v" == [[:blank:]]* || "$v" == *[[:blank:]] ]]; then
    echo 'a space or tab at the start or end'
  elif [[ "$v" == [\"\']* ]]; then
    echo 'a quote at the start'
  else
    return 1
  fi
}

function check_passwords () {
  local value why
  for value in "$HARBOR_PASSWORD" "$HARBOR_DB_PASSWORD"; do
    if [[ "$value" == *[[:cntrl:]]* ]]; then
      echo "Error: HARBOR_PASSWORD and HARBOR_DB_PASSWORD can't contain control characters."
      return 1
    fi
  done
  # Harbor's prepare writes the passwords into env files that docker compose reads by its own rules, so admin
  # would get a different password, and the installer's API calls a 401. Only the values passed reach this check:
  # a re-run reads harbor.yml's afterwards.
  if why=$(compose_changes "$HARBOR_PASSWORD"); then
    echo "Error: HARBOR_PASSWORD has $why. Harbor would create admin with a different password,"
    echo "  because docker compose changes that when it reads Harbor's env files. Nothing has been changed."
    echo "  Not allowed: a \$ before a letter, _, { or \$; a # after a space; a space or tab at the start or end; a quote at the start."
    return 1
  fi
  # The database password goes through the same rule in every file that holds it, so Harbor works, with a shorter one
  if why=$(compose_changes "$HARBOR_DB_PASSWORD"); then
    echo "  WARNING: HARBOR_DB_PASSWORD has $why. Harbor works, but docker compose gives Postgres a shorter"
    echo "  password than the one passed. Avoid a \$ before a letter, _, { or \$, a # after a space, spaces at either end, and a leading quote."
  fi
  return 0
}

# DURATION_DAYS is the server certificate's lifetime, CA_DURATION_DAYS a new CA's (H15)
function check_durations () {
  local name value
  for name in DURATION_DAYS CA_DURATION_DAYS; do
    value=${!name}
    if [[ ! "$value" =~ ^[0-9]+$ ]] || (( 10#$value < 1 )); then
      echo "Error: $name must be a whole number of days, at least 1 (got '$value'). Nothing has been changed."
      return 1
    fi
  done
  if (( 10#$CA_DURATION_DAYS < 10#$DURATION_DAYS )); then
    echo "Error: CA_DURATION_DAYS ($CA_DURATION_DAYS) is shorter than DURATION_DAYS ($DURATION_DAYS), and a certificate"
    echo "  can't outlive its CA. Nothing has been changed. Unset, CA_DURATION_DAYS takes DURATION_DAYS' value."
    return 1
  fi
}

# Harbor's rule for new users: 8 to 128 characters, with a lowercase letter, an uppercase letter and a number
function check_harbor_username () {
  [[ "$HARBOR_USERNAME" == "admin" ]] && return 0
  if [[ ! "$HARBOR_USERNAME" =~ ^[A-Za-z0-9._-]{1,255}$ ]]; then
    echo "Error: HARBOR_USERNAME '$HARBOR_USERNAME' can only use letters, numbers, dots, underscores and hyphens."
    return 1
  fi
  if [[ ${#HARBOR_PASSWORD} -lt 8 || ${#HARBOR_PASSWORD} -gt 128 || ! "$HARBOR_PASSWORD" =~ [a-z] || ! "$HARBOR_PASSWORD" =~ [A-Z] || ! "$HARBOR_PASSWORD" =~ [0-9] ]]; then
    echo "Error: HARBOR_USERNAME=$HARBOR_USERNAME needs a stronger HARBOR_PASSWORD. Harbor requires 8 to 128 characters,"
    echo "  with a lowercase letter, an uppercase letter and a number, for any user other than admin."
    return 1
  fi
}

# Nothing to do when the running stack is already what was asked for.
function harbor_unchanged () {
  [[ "${HARBOR_FORCE_REDEPLOY,,}" == "true" ]] && return 1
  [[ "$ca_rotation_due" -eq 1 ]] && return 1
  [[ -f "$install_env_file" && -f /opt/harbor/harbor.yml && -f /opt/harbor/docker-compose.yml ]] || return 1
  command -v docker >/dev/null 2>&1 || return 1
  [[ "$(get_install_env_value HARBOR_VERSION)" == "$HARBOR_VERSION" ]] || return 1
  [[ "$(docker inspect -f '{{.Config.Image}}' harbor-core 2>/dev/null)" == *":v$HARBOR_VERSION" ]] || return 1
  local total running rendered same=1
  total=$(docker compose -f /opt/harbor/docker-compose.yml ps -a --format '{{.Name}}' 2>/dev/null | wc -l)
  running=$(docker compose -f /opt/harbor/docker-compose.yml ps --status running --format '{{.Name}}' 2>/dev/null | wc -l)
  [[ "$total" -gt 0 && "$total" -eq "$running" ]] || return 1
  # harbor_admin_password only applies on a first install, so a difference there needs no redeploy
  rendered=$(mktemp)
  gen_harbor_yml "$rendered"
  cmp -s <(grep -v '^harbor_admin_password:' "$rendered") <(grep -v '^harbor_admin_password:' /opt/harbor/harbor.yml) || same=0
  rm -f "$rendered"
  [[ $same -eq 1 ]] || return 1
  server_cert_reusable
}

# --- Rollback for update-certificates --- #

cert_snapshot=""

function snapshot_for_cert_update () {
  local certsd="$docker_certs_root/$REGISTRY_COMMON_NAME:$HARBOR_PORT"
  cert_snapshot=$(mktemp -d /opt/harbor/.cert-update.XXXXXX) || return 1
  chmod 700 "$cert_snapshot"
  cp -a /opt/harbor/harbor.yml /opt/harbor/docker-compose.yml "$certs_dir" "$cert_snapshot/" || return 1
  [[ -d /opt/harbor/common/config ]] && { cp -a /opt/harbor/common/config "$cert_snapshot/common-config" || return 1; }
  [[ -f "$install_env_file" ]] && cp -a "$install_env_file" "$cert_snapshot/install-env"
  [[ -f "$certsd/ca.crt" ]] && cp -a "$certsd/ca.crt" "$cert_snapshot/certsd-ca.crt"
  [[ -f "$data_dir/ca_download/ca.crt" ]] && cp -a "$data_dir/ca_download/ca.crt" "$cert_snapshot/download-ca.crt"
  trap rollback_cert_update EXIT
}

function discard_cert_snapshot () {
  trap - EXIT
  [[ -n "$cert_snapshot" ]] && rm -rf "$cert_snapshot"
  cert_snapshot=""
}

# Any failure during update-certificates: put everything back, bring the stack up, and keep the failure's exit code
function rollback_cert_update () {
  local rc=$? certsd="$docker_certs_root/$REGISTRY_COMMON_NAME:$HARBOR_PORT" attempt code=""
  trap - EXIT
  [[ -n "$cert_snapshot" && -d "$cert_snapshot" ]] || exit "$rc"
  echo "ERROR: The certificate update failed. Restoring the previous certificates and restarting Harbor..." >&2
  rm -rf "$certs_dir"
  cp -a "$cert_snapshot/$(basename "$certs_dir")" "$certs_dir"
  cp -a "$cert_snapshot/harbor.yml" "$cert_snapshot/docker-compose.yml" /opt/harbor/
  if [[ -d "$cert_snapshot/common-config" ]]; then
    rm -rf /opt/harbor/common/config
    cp -a "$cert_snapshot/common-config" /opt/harbor/common/config
  fi
  [[ -f "$cert_snapshot/install-env" ]] && cp -a "$cert_snapshot/install-env" "$install_env_file"
  [[ -f "$cert_snapshot/certsd-ca.crt" ]] && cp -a "$cert_snapshot/certsd-ca.crt" "$certsd/ca.crt"
  [[ -f "$cert_snapshot/download-ca.crt" ]] && cp -a "$cert_snapshot/download-ca.crt" "$data_dir/ca_download/ca.crt"
  docker compose -f /opt/harbor/docker-compose.yml up -d >&2 || echo "ERROR: Harbor didn't restart. Check 'docker compose -f /opt/harbor/docker-compose.yml ps'." >&2
  for ((attempt = 1; attempt <= 36; attempt++)); do
    code=$(curl -sk -m 5 -o /dev/null -w '%{http_code}' "https://$mgmt_ip:$HARBOR_PORT/api/v2.0/ping" || true)
    [[ "$code" == "200" ]] && break
    heal_stale_proxy >&2
    sleep 5
  done
  if [[ "$code" == "200" ]]; then
    echo "  Harbor is back up with its previous certificates." >&2
    rm -rf "$cert_snapshot"
  else
    echo "ERROR: Harbor isn't answering after the rollback (last status: $code). The snapshot is kept in $cert_snapshot." >&2
  fi
  exit "$rc"
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
  # Matching the file proves nginx loaded it, not that any client will accept it
  if ! openssl verify -CAfile "$certs_dir/ca.crt" "$certs_dir/$REGISTRY_COMMON_NAME.crt" >/dev/null 2>&1; then
    echo "Error: $certs_dir/$REGISTRY_COMMON_NAME.crt doesn't verify against the CA in $certs_dir."
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
  # installed, not on whatever the current environment defaults to.
  # This merges with an earlier record. HARBOR_VERSION stays what's actually running until
  # commit_install_version, and earlier records of what this installer changed are kept.
  mkdir -p "$(dirname "$install_env_file")"
  local prior_version prior_users prior_ca
  prior_version=$(get_install_env_value HARBOR_VERSION)
  prior_users=$(docker_group_users)
  prior_ca=$(get_install_env_value CA_FINGERPRINT)
  cat > "$install_env_file" <<EOF
# Harbor install-time state - written by install_harbor.sh (no secrets stored here)
# Consumed by uninstall-harbor and update-certificates. Do not edit.
REGISTRY_COMMON_NAME=$REGISTRY_COMMON_NAME
HARBOR_PORT=$HARBOR_PORT
HARBOR_VERSION=$prior_version
HARBOR_VERSION_REQUESTED=$HARBOR_VERSION
HARBOR_USERNAME=$HARBOR_USERNAME
INSTALLER_VERSION=$SCRIPT_VERSION
INSTALL_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)
INSTALL_USER=$user_name
INSTALL_FILES_DIR=$base_dir/harbor-install-files
DOCKER_GROUP_USERS=$prior_users
CA_FINGERPRINT=$prior_ca
EOF
  chmod 600 "$install_env_file"
  echo "  Recorded install-time state in $install_env_file"
}

# The last step of a successful install: now the requested version really is what's running
function commit_install_version () {
  set_install_env_value HARBOR_VERSION "$HARBOR_VERSION"
  set_install_env_value HARBOR_VERSION_REQUESTED ""
}

# --- Version changes (H17, H18) --- #

# version_changing: data existed, and the version running before this run isn't the one asked for (or can't be told)
function version_changing () {
  [[ $data_preexisting -eq 1 && "$previous_version" != "$HARBOR_VERSION" ]]
}

# H17: dump the database before anything changes, so a failed upgrade can be rolled back. A failed or empty dump
# stops the run. Restore steps: README, "Restoring the database after a failed upgrade".
function dump_database_before_upgrade () {
  version_changing || return 0
  local from=${previous_version:-unknown} need free dump head_text
  if [[ "${HARBOR_DB_DUMP,,}" == "false" ]]; then
    echo "  WARNING: HARBOR_DB_DUMP=false: changing Harbor $from to $HARBOR_VERSION with no database dump."
    echo "  A failed upgrade can't be rolled back without one."
    return 0
  fi
  echo "  Harbor $from to $HARBOR_VERSION: dumping the database first..."
  need=$(du -sk "$data_dir/database" 2>/dev/null | cut -f1)
  free=$(df -Pk "$data_dir" 2>/dev/null | awk 'NR==2 {print $4}')
  if [[ ! "$need" =~ ^[0-9]+$ || ! "$free" =~ ^[0-9]+$ ]] || (( free < need )); then
    echo "Error: the database dump needs up to $(( ${need:-0} / 1024 )) MB free on $data_dir, and $(( ${free:-0} / 1024 )) MB is free."
    echo "  Nothing has been changed. Free some space, or set HARBOR_DB_DUMP=false to upgrade without a dump."
    return 1
  fi
  if [[ "$(docker inspect -f '{{.State.Running}}' harbor-db 2>/dev/null)" != "true" ]]; then
    if [[ ! -f /opt/harbor/docker-compose.yml ]]; then
      echo "Error: harbor-db isn't running and /opt/harbor/docker-compose.yml is gone, so the database can't be dumped."
      echo "  Nothing has been changed. HARBOR_DB_DUMP=false upgrades without a dump."
      return 1
    fi
    echo "  harbor-db isn't running: starting the installed version's database alone, for the dump..."
    docker compose -f /opt/harbor/docker-compose.yml up -d postgresql > /dev/null 2>&1 || true
  fi
  local attempt
  for attempt in {1..30}; do
    docker exec harbor-db pg_isready -U postgres > /dev/null 2>&1 && break
    sleep 2
  done
  if ! (umask 077; mkdir -p "$db_dump_dir") || ! chmod 700 "$db_dump_dir"; then
    echo "Error: can't create $db_dump_dir. Nothing has been changed."
    return 1
  fi
  dump="$db_dump_dir/harbor-db-v$from-$(date -u +%Y%m%d%H%M%S).sql.gz"
  # --clean --if-exists, so the dump loads over the fresh database a reinstall makes (README)
  if ! (set -o pipefail; umask 077; docker exec harbor-db pg_dumpall -U postgres --clean --if-exists | gzip > "$dump"); then
    rm -f "$dump"
    echo "Error: the database dump to $dump failed. Nothing has been changed."
    return 1
  fi
  head_text=$(gzip -dc "$dump" 2>/dev/null | head -c 4096 || true)
  if ! gzip -t "$dump" 2>/dev/null || ! grep -q 'PostgreSQL database cluster dump' <<< "$head_text"; then
    echo "Error: the database dump $dump is empty or incomplete. Nothing has been changed."
    return 1
  fi
  echo "  Dumped Harbor $from's database to $dump ($(du -h "$dump" | cut -f1))."
  echo "  To roll back a failed upgrade, see the README: Restoring the database after a failed upgrade."
}

# old_harbor_images: goharbor/* images of other versions that no container uses, one per line
function old_harbor_images () {
  local keep="v$HARBOR_VERSION" used img
  used=$(docker ps -a --format '{{.Image}}' 2>/dev/null)
  while read -r img; do
    [[ -n "$img" && "$img" != *":<none>" && "${img##*:}" != "$keep" ]] || continue
    grep -qxF "$img" <<< "$used" && continue
    echo "$img"
  done < <(docker images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | grep '^goharbor/' || true)
}

# H18: after a successful version change, free the space the other versions' images take. Never fails the run.
function remove_old_images () {
  version_changing || return 0
  if [[ "${HARBOR_REMOVE_OLD_IMAGES,,}" == "false" ]]; then
    echo "  HARBOR_REMOVE_OLD_IMAGES=false: keeping the goharbor images of earlier versions."
    return 0
  fi
  local images=() img removed=0 root before after
  readarray -t images < <(old_harbor_images)
  [[ ${#images[@]} -gt 0 ]] || return 0
  # Images share layers, so what they list adds up to more than is freed: measure the disk instead
  root=$(docker info -f '{{.DockerRootDir}}' 2>/dev/null || true)
  before=$(df -Pk "${root:-/var/lib/docker}" 2>/dev/null | awk 'NR==2 {print $4}')
  for img in "${images[@]}"; do
    if docker rmi "$img" > /dev/null 2>&1; then
      removed=$((removed + 1))
    else
      echo "  WARNING: couldn't remove $img."
    fi
  done
  after=$(df -Pk "${root:-/var/lib/docker}" 2>/dev/null | awk 'NR==2 {print $4}')
  if [[ "$before" =~ ^[0-9]+$ && "$after" =~ ^[0-9]+$ ]] && (( after >= before )); then
    echo "  Removed $removed goharbor image(s) of earlier Harbor versions, freeing $(( (after - before) / 1024 )) MB."
  else
    echo "  Removed $removed goharbor image(s) of earlier Harbor versions."
  fi
  local tgz="$base_dir/harbor-install-files/harbor-offline-installer-v$previous_version.tgz"
  if [[ -n "$previous_version" && -f "$tgz" ]]; then
    echo "  Kept $tgz ($(du -h "$tgz" | cut -f1)): a rollback needs it. Delete it once the upgrade is trusted."
  fi
}

# Users this installer added to the docker group. Older installs recorded a flag and one user.
function docker_group_users () {
  [[ -f "$install_env_file" ]] || return 0
  if grep -q '^DOCKER_GROUP_USERS=' "$install_env_file"; then
    get_install_env_value DOCKER_GROUP_USERS
  elif [[ "$(get_install_env_value DOCKER_GROUP_ADDED)" == "1" ]]; then
    get_install_env_value INSTALL_USER
  fi
}

function record_docker_group_user () {
  local users
  users=$(docker_group_users)
  case " $users " in
    *" $1 "*) ;;
    *) set_install_env_value DOCKER_GROUP_USERS "${users:+$users }$1" ;;
  esac
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
  recorded_docker_users=$(docker_group_users)
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

# write_api_cfg <file> <user> <password>: credentials for curl -K, so they stay off argv
function write_api_cfg () {
  (umask 077; printf 'user = "%s:%s"\n' "$(dq_escape "$2")" "$(dq_escape "$3")" > "$1")
}

function api_code () { # api_code <cfg> <path>
  curl -s -o /dev/null -w "%{http_code}" -K "$1" -k "https://$mgmt_ip:$HARBOR_PORT/api/v2.0/$2"
}

# ensure_harbor_user: make HARBOR_USERNAME a system administrator. Harbor can't rename admin, so this is a second
# account, and admin stays. It never resets anything: a clash is reported, and left for you to sort out.
function ensure_harbor_user () {
  local admin_cfg=$1 named_cfg=$2 code id tmp email
  tmp=$(mktemp)
  code=$(curl -s -o "$tmp" -w "%{http_code}" -K "$named_cfg" -k "https://$mgmt_ip:$HARBOR_PORT/api/v2.0/users/current")
  if [[ "$code" == "200" ]] && grep -q '"sysadmin_flag": *true' "$tmp"; then
    echo "  Administrator '$HARBOR_USERNAME' already exists."
    rm -f "$tmp"
    return 0
  fi
  if [[ "$code" == "200" ]]; then
    id=$(grep -o '"user_id": *[0-9]*' "$tmp" | grep -o '[0-9]*$')
  else
    email=${HARBOR_USER_EMAIL:-$HARBOR_USERNAME@$REGISTRY_COMMON_NAME}
    code=$(curl -s -D "$tmp" -o /dev/null -w "%{http_code}" -X POST -H "Content-Type: application/json" -K "$admin_cfg" -k \
      --data-binary @- "https://$mgmt_ip:$HARBOR_PORT/api/v2.0/users" <<JSON
{"username": "$HARBOR_USERNAME", "email": "$(dq_escape "$email")", "realname": "$HARBOR_USERNAME", "password": "$(dq_escape "$HARBOR_PASSWORD")"}
JSON
)
    if [[ "$code" == "409" ]]; then
      echo "  CRITICAL: Harbor user '$HARBOR_USERNAME' already exists with a different password. Nothing was changed."
      rm -f "$tmp"
      return 1
    fi
    if [[ "$code" != "201" ]]; then
      echo "  CRITICAL: Harbor refused to create user '$HARBOR_USERNAME' (HTTP $code)."
      rm -f "$tmp"
      return 1
    fi
    id=$(tr -d '\r' < "$tmp" | sed -n 's|^[Ll]ocation: .*/users/\([0-9]*\)$|\1|p')
  fi
  rm -f "$tmp"
  if [[ -z "$id" ]]; then
    echo "  CRITICAL: Could not find the ID of Harbor user '$HARBOR_USERNAME'."
    return 1
  fi
  code=$(curl -s -o /dev/null -w "%{http_code}" -X PUT -H "Content-Type: application/json" -K "$admin_cfg" -k \
    -d '{"sysadmin_flag": true}' "https://$mgmt_ip:$HARBOR_PORT/api/v2.0/users/$id/sysadmin")
  if [[ "$code" != "200" ]]; then
    echo "  CRITICAL: Could not make '$HARBOR_USERNAME' a system administrator (HTTP $code)."
    return 1
  fi
  echo "  Created administrator '$HARBOR_USERNAME'."
}

# Harbor's core can crash once on first boot while its database is still starting, then come back on a new address.
# Another container can take the old one, and nginx keeps sending API calls to it, so they all get that container's 401.
# Restarting nginx fixes it. This only acts when core answers directly and the same call through nginx doesn't.
function heal_stale_proxy () {
  [[ "$(docker exec harbor-core curl -s -m 5 http://localhost:8080/api/v2.0/ping 2>/dev/null)" == "Pong" ]] || return 0
  [[ "$(curl -sk -m 5 "https://$mgmt_ip:$HARBOR_PORT/api/v2.0/ping" 2>/dev/null)" != "Pong" ]] || return 0
  echo "  nginx is sending API calls to the wrong container, because Harbor's core moved while starting. Restarting nginx..."
  docker restart nginx >/dev/null 2>&1 || true
}

# wait_for_harbor_api: the API answers through nginx within HARBOR_API_WAIT_SEC.
function wait_for_harbor_api () {
  local attempt max_attempts=$((HARBOR_API_WAIT_SEC / 5))
  for ((attempt = 1; attempt <= max_attempts; attempt++)); do
    [[ "$(curl -sk -m 5 "https://$mgmt_ip:$HARBOR_PORT/api/v2.0/ping" 2>/dev/null)" == "Pong" ]] && return 0
    heal_stale_proxy
    sleep 5
  done
  return 1
}

create_harbor_projects() {
    local wait_seconds=5
    local max_attempts=$((HARBOR_API_WAIT_SEC / wait_seconds))
    local attempt=1
    local connected=false
    local health_status=""
    local rc=0
    local curl_cfg admin_cfg named_cfg=""
    read -r -a PROJECTS_ARRAY <<< "$PROJECTS"
    # Keep credentials off argv: pass them to curl via a root-only config file
    admin_cfg=$(mktemp)
    write_api_cfg "$admin_cfg" admin "$HARBOR_PASSWORD"
    curl_cfg=$admin_cfg
    if [[ "$HARBOR_USERNAME" != "admin" ]]; then
        named_cfg=$(mktemp)
        write_api_cfg "$named_cfg" "$HARBOR_USERNAME" "$HARBOR_PASSWORD"
    fi
    # 1. Connectivity & Auth Pre-Check with Retry Loop
    echo "  Starting Harbor API health check (Timeout: ${HARBOR_API_WAIT_SEC}s)..."

    while [ $attempt -le $max_attempts ]; do
        # The named account first, because admin's password may have been changed in the UI since
        if [[ -n "$named_cfg" && "$(api_code "$named_cfg" 'projects?page_size=1')" == "200" ]]; then
            echo "  Connection successful on attempt $attempt."
            connected=true
            break
        fi
        health_status=$(api_code "$admin_cfg" 'projects?page_size=1')

        if [[ "$health_status" == "200" ]]; then
            echo "  Connection successful on attempt $attempt."
            connected=true
            break
        fi

        echo "  Attempt $attempt/$max_attempts: Harbor API not ready (Status: $health_status). Retrying in ${wait_seconds}s..."
        heal_stale_proxy
        sleep $wait_seconds
        ((attempt++))
    done

    if [ "$connected" = false ]; then
        rm -f "$admin_cfg" "$named_cfg"
        if [[ "$health_status" == "401" ]]; then
            echo "  CRITICAL: Harbor API rejected the credentials (HTTP 401)."
            if [[ $data_preexisting -eq 1 ]]; then
                echo "  This install reused existing Harbor data in $data_dir - the ORIGINAL admin password is in effect, not the HARBOR_PASSWORD passed to this run."
            fi
        else
            echo "  CRITICAL: Harbor API remained unreachable after ${HARBOR_API_WAIT_SEC} seconds (last status: $health_status). HARBOR_API_WAIT_SEC allows longer."
        fi
        return 1
    fi

    if [[ -n "$named_cfg" ]]; then
        if ! ensure_harbor_user "$admin_cfg" "$named_cfg"; then
            rm -f "$admin_cfg" "$named_cfg"
            return 1
        fi
        curl_cfg=$named_cfg
    fi

    # 2. Loop through the PROJECTS array
    if [[ -z "${PROJECTS_ARRAY[*]}" ]]; then
        echo "  No projects defined in the list. Skipping project creation..."
        rm -f "$admin_cfg" "$named_cfg"
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
    rm -f "$admin_cfg" "$named_cfg"
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

# gen_harbor_yml [path]: renders harbor.yml, by default to where Harbor reads it
function gen_harbor_yml () {
  local dest=${1:-/opt/harbor/harbor.yml}
  mkdir -p "$(dirname "$dest")"
  cat > "$dest" <<EOF
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
harbor_admin_password: "$(dq_escape "$HARBOR_PASSWORD")"

# Harbor DB configuration
database:
  # The password for the user('postgres' by default) of Harbor DB. Change this before any production use.
  password: "$(dq_escape "$HARBOR_DB_PASSWORD")"
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
  chmod 600 "$dest"
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
  echo "version                 | Prints this script's version"
}

# When sourced (e.g. by a test harness), stop here without running the CLI wrapper
if [[ "${BASH_SOURCE[0]:-$0}" != "$0" ]]; then
  return 0
fi

# Start CLI Wrapper
while [[ $# -gt 0 ]]; do
  case "$1" in
    help|-h|--help)
      help
      exit 0
      ;;
    version|--version)
      echo "$SCRIPT_VERSION"
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
      select_docker_packages save
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
