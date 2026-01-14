#!/bin/bash

# This script contains functions for installing a Harbor registry on Ubuntu for storing container images

# --- User Defined Variables --- #
DEBUG=${DEBUG:-1}

# Harbor configuration
HARBOR_VERSION=${HARBOR_VERSION:-2.14.1}
HARBOR_PORT=${HARBOR_PORT:-443}
HARBOR_USERNAME=${HARBOR_USERNAME:-admin}
HARBOR_PASSWORD=${HARBOR_PASSWORD:-Harbor12345}
DOCKER_BRIDGE_CIDR=${DOCKER_BRIDGE_CIDR:-"172.30.0.1/16"}
PROJECTS=${PROJECTS:-""}

# Self-signed certificate 
COUNTRY=${COUNTRY:-"US"}
STATE=${STATE:-"MA"}
LOCATION=${LOCATION:-"BOSTON"}
ORGANIZATION=${ORGANIZATION:-"SELF"}
REGISTRY_COMMON_NAME=${REGISTRY_COMMON_NAME:-"regsitry.edge.lab"}
DURATION_DAYS=${DURATION_DAYS:-"3650"}

# --- INTERNAL VARIABLES (do not edit) --- #
DOCKER_PACKAGES=(docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin)
base_dir=$(pwd)
os_id=""
mgmt_ip=$(hostname -I | awk '{print $1}')
mgmt_if=$(ip a |grep "$(hostname -I |awk '{print $1}')" | awk '{print $NF}')
user_name=${SUDO_USER:-$(whoami)}
current_hostname=$(hostname)

#### --- Functions --- ###

# --- Menu Functions --- #

function install_harbor {
  debug_run install_docker_utility
  debug_run cert_gen
  debug_run harbor_cert_install
  debug_run gen_harbor_yml
  debug_run run_harbor_installer
  debug_run create_harbor_service
  debug_run create_harbor_projects
  echo "# ---  Harbor Install Completed! --- #"
  echo "  Harbor install and compose files are in /opt/harbor and /data directories"
  echo "  Harbor Version: $HARBOR_VERSION"
  echo "  URL: https://$mgmt_ip:$HARBOR_PORT"
  echo "  FQDN URL: https://$REGISTRY_COMMON_NAME:$HARBOR_PORT"
  echo "  Username: $HARBOR_USERNAME"
  echo "  Password: $HARBOR_PASSWORD"
}

function uninstall_harbor {
  echo "  Uninstalling Harbor registry"
  echo "  Removing containers..."
  docker compose -f /opt/harbor/docker-compose.yml down
  systemctl disable --now harbor-docker.service
  echo "  Removing data files..."
  rm -rf $base_dir/harbor-install-files
  rm -rf /opt/harbor
  rm -rf /data
  rm -f /etc/systemd/system/harbor-docker.service
  rm -rf "/etc/docker/certs.d/$REGISTRY_COMMON_NAME:$HARBOR_PORT" 
  echo "  Uninstallation completed..."
}

function harbor_offline_prep {
  echo "  Preparing an offline package for Harbor registry..."
  debug_run apt_download_packs
  debug_run download_harbor_offline_package
  debug_run prepare_offline_package
  echo "  Offline package generation completed..."
  echo "  Upload harbor-offline-package.tar.gz to your airgapped system running $os_release_version"
}



function update_certificates {
  echo "soon..."
}

# --- Install Harbor Functions --- #

os_type() {
    # Get OS information from /etc/os-release
    if [[ -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
        source /etc/os-release
        echo "  OS type is: $ID"
        os_id="$ID"
    else
        echo "Unknown or unsupported OS $os_id."
        exit 1
    fi
}

function add_docker_repo () {
    os_type
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
        rhel|rocky|almalinux)
            dnf config-manager --add-repo https://download.docker.com/linux/rhel/docker-ce.repo
            ;;
        centos)
            dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
            ;;
        fedora)
            dnf-3 config-manager --add-repo https://download.docker.com/linux/fedora/docker-ce.repo
            ;;
        *)
            echo "Error: Unsupported OS '$os_id'. Manual install of Docker required."
            rm -rf /etc/docker
            exit 1
            ;;
    esac
}

function install_packages_check () {
    if [[ ! -f $base_dir/harbor-install-files/apt-packages/install_packages.sh ]]; then
        mkdir -p "$base_dir/harbor-install-files/apt-packages"
        echo "  Downloading install_packages.sh..."
        curl -sfL https://github.com/Chubtoad5/install-packages/raw/refs/heads/main/install_packages.sh  -o "$base_dir/harbor-install-files/apt-packages/install_packages.sh"
        chmod +x $base_dir/harbor-install-files/apt-packages/install_packages.sh
    fi
}

function install_docker_utility() {
    install_packages_check
    cd $base_dir/harbor-install-files/apt-packages
    if [[ -f  $base_dir/harbor-install-files/apt-packages/offline-packages.tar.gz ]]; then
        ./install_packages.sh offline "${DOCKER_PACKAGES[@]}"
    else
        add_docker_repo
        ./install_packages.sh online "${DOCKER_PACKAGES[@]}"
    fi
    systemctl enable --now docker || true
    usermod -aG docker $user_name
    cd $base_dir
}

function create_bridge_json () {
  mkdir -p /etc/docker
  cat <<EOF | tee /etc/docker/daemon.json > /dev/null
{
  "bip": "$DOCKER_BRIDGE_CIDR"
}
EOF
  echo "  Created /etc/docker/daemon.json with bip: $DOCKER_BRIDGE_CIDR"
}

function cert_gen () {
  echo "  Creating self-signed certificate valid for $DURATION_DAYS days..."
  mkdir -p $base_dir/harbor-install-files/certs
  # Generate CA key
  openssl genrsa -out $base_dir/harbor-install-files/certs/ca.key 4096
  # Generate CA certificate
  openssl req -x509 -new -nodes -sha512 -days $DURATION_DAYS -subj "/C=$COUNTRY/ST=$STATE/L=$LOCATION/O=$ORGANIZATION/CN=$REGISTRY_COMMON_NAME" -key $base_dir/harbor-install-files/certs/ca.key -out $base_dir/harbor-install-files/certs/ca.crt
  # Generate server key
  openssl genrsa -out $base_dir/harbor-install-files/certs/$REGISTRY_COMMON_NAME.key 4096
  # Generate server CSR
  openssl req -sha512 -new -subj "/C=$COUNTRY/ST=$STATE/L=$LOCATION/O=$ORGANIZATION/CN=$REGISTRY_COMMON_NAME" -key $base_dir/harbor-install-files/certs/$REGISTRY_COMMON_NAME.key -out $base_dir/harbor-install-files/certs/$REGISTRY_COMMON_NAME.csr
  # Create v3 extension
  cat > $base_dir/harbor-install-files/certs/v3.ext <<EOF
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
  openssl x509 -req -sha512 -days $DURATION_DAYS -extfile $base_dir/harbor-install-files/certs/v3.ext -CA $base_dir/harbor-install-files/certs/ca.crt -CAkey $base_dir/harbor-install-files/certs/ca.key -CAcreateserial -in $base_dir/harbor-install-files/certs/$REGISTRY_COMMON_NAME.csr -out $base_dir/harbor-install-files/certs/$REGISTRY_COMMON_NAME.crt
  # Convert signed certificate from .crt to .cert
  openssl x509 -inform PEM -in $base_dir/harbor-install-files/certs/$REGISTRY_COMMON_NAME.crt -out $base_dir/harbor-install-files/certs/$REGISTRY_COMMON_NAME.cert
  echo "Certificat generation completed..."
}

function harbor_cert_install () {
    
  #Copy certs
  mkdir -p "/data/ca_download"
  mkdir -p "/etc/docker/certs.d/$REGISTRY_COMMON_NAME:$HARBOR_PORT"
  cp $base_dir/harbor-install-files/certs/$REGISTRY_COMMON_NAME.cert /etc/docker/certs.d/$REGISTRY_COMMON_NAME:$HARBOR_PORT/
  cp $base_dir/harbor-install-files/certs/$REGISTRY_COMMON_NAME.key /etc/docker/certs.d/$REGISTRY_COMMON_NAME:$HARBOR_PORT/
  cp $base_dir/harbor-install-files/certs/ca.crt /etc/docker/certs.d/$REGISTRY_COMMON_NAME:$HARBOR_PORT/
  # cp $base_dir/harbor-install-files/certs/$REGISTRY_COMMON_NAME.crt /usr/local/share/ca-certificates/
  cp $base_dir/harbor-install-files/certs/$REGISTRY_COMMON_NAME.crt /data/ca_download/ca.crt

  # Update certificate store
  # update-ca-certificates

  # Restart docker
  systemctl restart docker
}

function run_harbor_installer() {
  if [ -f $base_dir/harbor-install-files/VERSION.txt ]; then
    tar xzvf $base_dir/harbor-install-files/harbor-offline-installer-v$HARBOR_VERSION.tgz -C /opt/
  else
    curl -fsSLo $base_dir/harbor-install-files/harbor-offline-installer-v$HARBOR_VERSION.tgz https://github.com/goharbor/harbor/releases/download/v$HARBOR_VERSION/harbor-offline-installer-v$HARBOR_VERSION.tgz
    tar xzvf $base_dir/harbor-install-files/harbor-offline-installer-v$HARBOR_VERSION.tgz -C /opt/
  fi
  /opt/harbor/install.sh
  echo "  creating crumb file..."
  cat > $base_dir/harbor-install-files/read_this_crumb.txt <<EOF
Harbor install files are located in /opt/harbor and /data directories
Version: $HARBOR_VERSION
URL: https://$mgmt_ip:$HARBOR_PORT
FQDN URL: https://$REGISTRY_COMMON_NAME:$HARBOR_PORT
Default Username: $HARBOR_USERNAME
Default Password: $HARBOR_PASSWORD
EOF
}

function create_harbor_service () {
    echo "  Creating Habor systemd service..."
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
}


# --- Offline Prep Functions --- #

function apt_download_packs () {
  install_packages_check
  add_docker_repo
  cd $base_dir/harbor-install-files/apt-packages
  ./install_packages.sh save "${DOCKER_PACKAGES[@]}"
  cd $base_dir
}

function download_harbor_offline_package() {
  curl -fsSLo $base_dir/harbor-install-files/harbor-offline-installer-v$HARBOR_VERSION.tgz https://github.com/goharbor/harbor/releases/download/v$HARBOR_VERSION/harbor-offline-installer-v$HARBOR_VERSION.tgz
}

function prepare_offline_package() {
  echo "  Generating offline archive..."
  cd $base_dir
  echo "Offline package generated on $(date) for $os_release_version and Harbor version $HARBOR_VERSION" | tee $base_dir/harbor-install-files/VERSION.txt
  tar czvf harbor-offline-package.tar.gz harbor-install-files/ install_harbor.sh
}

# --- Update Certificate Functions --- #

function new_cert_check() {
  echo "soon..."
  # Develop a function to check for $NEW_CERT_GEN to determine if a new self-signed certificate is to be generated, then do it
  # If user supplies certs, use openssl to verify and get the common name
  # stop harbor contaners
  # copy to docker certs.d with new common name and restart
  # copy to /usr/local/share/ca-certificates
  # update-ca-certificates and restart docker
  # copy to /data/ca_download
  # bring up containers
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

create_harbor_projects() {
    local max_attempts=6
    local wait_seconds=5
    local attempt=1
    local connected=false
    read -a PROJECTS_ARRAY <<< "$PROJECTS"
    # 1. Connectivity & Auth Pre-Check with Retry Loop
    echo "  Starting Harbor API health check (Timeout: 30s)..."
    
    while [ $attempt -le $max_attempts ]; do
        local health_status=$(curl -s -o /dev/null -w "%{http_code}" \
            -u "$HARBOR_USERNAME:$HARBOR_PASSWORD" -k \
            "https://$REGISTRY_COMMON_NAME:$HARBOR_PORT/api/v2.0/projects?page_size=1")

        if [[ "$health_status" == "200" ]]; then
            echo "  Connection successful on attempt $attempt."
            connected=true
            break
        fi

        echo "  Attempt $attempt/$max_attempts: Harbor API unreachable (Status: $health_status). Retrying in ${wait_seconds}s..."
        sleep $wait_seconds
        ((attempt++))
    done

    if [ "$connected" = false ]; then
        echo "  CRITICAL: Harbor API remained unreachable after 30 seconds."
        return 0
    fi

    # 2. Loop through the PROJECTS array
    if [[ -z "${PROJECTS_ARRAY[*]}" ]]; then
        echo "  No projects defined in the list. Skipping project creation..."
        return 0
    fi
    echo "  Found projects to create"
    for REGISTRY_PROJECT_NAME in "${PROJECTS_ARRAY[@]}"; do
        echo "  Processing project: $REGISTRY_PROJECT_NAME"

        local check_cmd="curl -s -u \"$HARBOR_USERNAME:$HARBOR_PASSWORD\" -k \"https://$REGISTRY_COMMON_NAME:$HARBOR_PORT/api/v2.0/projects?name=$REGISTRY_PROJECT_NAME\""
        
        # Check if project exists
        local exists=$(eval "$check_cmd" | grep -o '"name":"'$REGISTRY_PROJECT_NAME'"' | awk -F':' '{print $2}' | tr -d '"')

        if [[ "$exists" == "$REGISTRY_PROJECT_NAME" ]]; then
            echo "  Result: Project '$REGISTRY_PROJECT_NAME' already exists."
        else
            # 3. Create the project            
            local create_status=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
                -H "Content-Type: application/json" \
                -u "$HARBOR_USERNAME:$HARBOR_PASSWORD" \
                -k -d "{ \"project_name\": \"$REGISTRY_PROJECT_NAME\", \"public\": false }" \
                "https://$REGISTRY_COMMON_NAME:$HARBOR_PORT/api/v2.0/projects")

            # 4. Final Verification
            local verified=$(eval "$check_cmd" | grep -o '"name":"'$REGISTRY_PROJECT_NAME'"' | awk -F':' '{print $2}' | tr -d '"')

            if [[ "$verified" == "$REGISTRY_PROJECT_NAME" ]]; then
                echo "  Success: Project '$REGISTRY_PROJECT_NAME' verified (HTTP $create_status)."
            else
                echo "  Failure: Project '$REGISTRY_PROJECT_NAME' creation failed (HTTP $create_status)."
                return 0
            fi
        fi
    done
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
  [ -f /opt/harbor/harbor.yml ] || mkdir -p /opt/harbor
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
  certificate: "$base_dir/harbor-install-files/certs/$REGISTRY_COMMON_NAME.crt"
  private_key: "$base_dir/harbor-install-files/certs/$REGISTRY_COMMON_NAME.key"
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
  password: root123
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

}

# --- Main Menu function --- #

function help {
  echo "Usage: $0 [parameter]"
  echo ""
  echo "[Parameters]            | [Description]"
  echo "help                    | Display this help message"
  echo "install-harbor          | Installs Harbor regsitry"
  echo "uninstall-harbor        | Uninstalls Harbor registry"
  echo "offline-prep            | Prepares an offline package"
  echo "update-certificates     | Installs helm chart from variables"
}

# Start CLI Wrapper
while [[ $# -gt 0 ]]; do
  case "$1" in
    help)
      help
      exit 0
      ;;
    install-harbor)
      check_root_privileges
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
      echo "###   Harbor Offline Preparation Started - $(date)   ###"
      harbor_offline_prep
      echo "###   Harbor Offline Preparation Finished - $(date)   ###"
      exit 0
      ;;
    update-certificates)
      check_root_privileges
      echo "###   Update Certificattes Started - $(date)  ###"
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