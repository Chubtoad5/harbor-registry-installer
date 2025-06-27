#!/bin/bash

# This script contains functions for installing a Harbor registry on Ubuntu for storing container images

# --- User Defined Variables --- #
DEBUG=true

# Harbor configuration
HARBOR_VERSION=2.12.2
HARBOR_PORT=443
HARBOR_USERNAME=admin
HARBOR_PASSWORD=Harbor12345
DOCKER_BRIDGE_CIDR=172.30.0.1/16

# Self-signed certificate 
DURATION_DAYS=3650
REGISTRY_COMMON_NAME=regsitry.local.edge
COUNTRY=US
STATE=MA
LOCATION=LAB
ORGANIZATION=SELF

# Offline Prep Parameters

OFFLINE_APT_PACKAGES=(docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin)


# --- INTERNAL VARIABLES (do not edit) --- #
base_dir=$(pwd)
os_release_version=$(lsb_release -ds |tail -1)
os_release_version_short=$(lsb_release -rs |tail -1)
mgmt_ip=$(hostname -I | awk '{print $1}')
mgmt_if=$(ip a |grep "$(hostname -I |awk '{print $1}')" | awk '{print $NF}')
user_name=$SUDO_USER
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
  echo "# ---  Harbor Install Completed! --- #"
  echo "  Harbor Version: $HARBOR_VERSION"
  echo "  URL: https://$mgmt_ip:$HARBOR_PORT"
  echo "  FQDN URL: https://$REGISTRY_COMMON_NAME:$HARBOR_PORT"
  echo "  Username: $HARBOR_USERNAME"
  echo "  Password: $HARBOR_PASSWORD"
}

function uninstall_harbor {
  echo "Uninstalling Harbor registry"
  echo "Removing containers..."
  docker compose -f $base_dir/harbor-install-files/harbor/docker-compose.yml down
  systemctl disable --now harbor-docker.service
  echo "Removing data files..."
  rm -rf $base_dir/harbor-install-files
  rm -rf /data
  rm -f /etc/systemd/system/harbor-docker.service
  rm -rf "/etc/docker/certs.d/$REGISTRY_COMMON_NAME:$HARBOR_PORT" 
  echo "Uninstallation completed..."
}

function harbor_offline_prep {
  echo "Preparing an offline package for Harbor registry..."
  [ -d "$base_dir/harbor-install-files/apt-packages" ] || mkdir -p "$base_dir/harbor-install-files/apt-packages"
  debug_run apt_get_install dpkg-dev
  cd $base_dir/harbor-install-files/apt-packages
  debug_run apt_download_packs
  debug_run download_harbor_offline_package
  debug_run prepare_offline_package
  echo "Offline package generation completed..."
  echo "Upload harbor-offline-package.tar.gz to your airgapped system running $os_release_version"
}

function update_certificates {
  echo "soon..."
}

# --- Install Harbor Functions --- #

function install_docker_utility() {
  if [ -f $base_dir/harbor-install-files/VERSION.txt ]; then
    echo "deb [trusted=yes] file:$base_dir/harbor-install-files/apt-packages ./" | tee -a /etc/apt/sources.list.d/extra-packages.list
    echo "Backing up original apt sources for offline installation..."
    mv /etc/apt/sources.list /etc/apt/sources.list.bak
    [ $os_release_version_short = "22.04" ] || mv /etc/apt/sources.list.d/ubuntu.sources /etc/apt/sources.list.d/ubuntu.sources.bak
    [ ! -f /etc/apt/sources.list.d/docker.list ] || mv /etc/apt/sources.list.d/docker.list /etc/apt/sources.list.d/docker.list.bak
  fi
  if [ ! -f $base_dir/harbor-install-files/VERSION.txt ]; then
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
    chmod a+r /etc/apt/keyrings/docker.asc
    echo \
      "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
      $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}") stable" | \
      sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
  fi
  apt-get update
  create_bridge_json
  echo "" | DEBIAN_FRONTEND=noninteractive apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  usermod -aG docker $user_name
  if [ -f $base_dir/harbor-install-files/VERSION.txt ]; then
    echo "Reverting apt sources..."
    mv /etc/apt/sources.list.bak /etc/apt/sources.list
    [ $os_release_version_short = "22.04" ] || mv /etc/apt/sources.list.d/ubuntu.sources.bak /etc/apt/sources.list.d/ubuntu.sources
    [ ! -f /etc/apt/sources.list.d/docker.list.bak ] || mv /etc/apt/sources.list.d/docker.list.bak /etc/apt/sources.list.d/docker.list
    rm /etc/apt/sources.list.d/extra-packages.list
  fi
}

function create_bridge_json () {
  echo "pre-creating docker bridge json..."
  mkdir -p /etc/docker
  cat <<EOF | tee /etc/docker/daemon.json > /dev/null
{
  "bip": "$DOCKER_BRIDGE_CIDR"
}
EOF
  echo "Created /etc/docker/daemon.json with bip: $DOCKER_BRIDGE_CIDR"
}

function cert_gen () {
  echo "Creating self-signed certificate valid for $DURATION_DAYS days..."
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
DNS.1=$REGISTRYT_COMMON_NAME
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
  cp $base_dir/harbor-install-files/certs/$REGISTRY_COMMON_NAME.crt /usr/local/share/ca-certificates/
  cp $base_dir/harbor-install-files/certs/$REGISTRY_COMMON_NAME.crt /data/ca_download/ca.crt

  # Update certificate store
  update-ca-certificates

  # Restart docker
  systemctl restart docker
}

function run_harbor_installer() {
  if [ -f $base_dir/harbor-install-files/VERSION.txt ]; then
    tar xzvf $base_dir/harbor-install-files/harbor-offline-installer-v$HARBOR_VERSION.tgz
  else
    curl -fsSLo $base_dir/harbor-install-files/harbor-offline-installer-v$HARBOR_VERSION.tgz https://github.com/goharbor/harbor/releases/download/v$HARBOR_VERSION/harbor-offline-installer-v$HARBOR_VERSION.tgz
    tar xzvf $base_dir/harbor-install-files/harbor-offline-installer-v$HARBOR_VERSION.tgz -C $base_dir/harbor-install-files/
  fi
  $base_dir/harbor-install-files/harbor/install.sh
}

function create_harbor_service () {
    echo "Creating Habor systemd service..."
    cat > /etc/systemd/system/harbor-docker.service <<EOF
[Unit]
Description=Harbor
After=docker.service systemd-networkd.service systemd-resolved.service
Requires=docker.service

[Service]
Type=forking
Restart=on-failure
RestartSec=5
ExecStart=/usr/bin/docker compose -f $base_dir/harbor-install-files/harbor/docker-compose.yml up -d
ExecStop=/usr/bin/docker compose -f $base_dir/harbor-install-files/harbor/docker-compose.yml down
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
    echo "Downloading "${OFFLINE_APT_PACKAGES[*]}" ..."
    apt-get download $(apt-cache depends --recurse --no-recommends --no-suggests --no-conflicts --no-breaks --no-replaces --no-enhances --no-pre-depends ${OFFLINE_APT_PACKAGES[*]} | grep "^\w")
    dpkg-scanpackages -m . > Packages
    echo "Completed downloading..."
}

function download_harbor_offline_package() {
  curl -fsSLo $base_dir/harbor-install-files/harbor-offline-installer-v$HARBOR_VERSION.tgz https://github.com/goharbor/harbor/releases/download/v$HARBOR_VERSION/harbor-offline-installer-v$HARBOR_VERSION.tgz
}

function prepare_offline_package() {
  echo "Generating offline archive..."
  cd $base_dir
  echo "Offline package generated on $(date) for $os_release_version and Harbor version $HARBOR_VERSION" | tee $base_dir/harbor-install-files/VERSION.txt
  tar czvf harbor-offline-package.tar.gz harbor-install-files/ install_harbor.sh
}

# --- Update Certificate Functions --- #

function new_cert_check() {
  echo "soon..."
  # Develop a function to cehck for $NEW_CERT_GEN to determine if a new self-signed certificate is to be generated, then do it
  # If user supplies certs, use openssl to verify and get the common name
  # stop harbor contaners
  # copy to docker certs.d with new common name and restart
  # copy to /usr/local/share/ca-certificates
  # update-ca-certificates and restart docker
  # copy to /data/ca_download
  # bring up containers
}

# --- Utility Functions --- #

function apt_get_install() {
  echo "Installing $1..."
  apt-get update
  # Add a check for successful update before installing
  if [ $? -ne 0 ]; then
    echo "ERROR: apt-get update failed."
    return 1 # Indicate failure
  fi
  echo "" | DEBIAN_FRONTEND=noninteractive apt-get -y -qq install "$1"
  # Check for successful install
  if [ $? -ne 0 ]; then
    echo "ERROR: Failed to install $1."
    return 1 # Indicate failure
  fi
  echo "$1 installed successfully."
  return 0 # Indicate success
}

function debug_run() {
  # Check the value of the global DEBUG variable
  if [ "$DEBUG" = "true" ]; then
    # If DEBUG is true, execute the command/function normally.
    # All stdout and stderr will be displayed to the console.
    echo "--- DEBUG: Running '$*' ---"
    "$@"
    local status=$? # Capture the exit status of the executed command
    echo "--- DEBUG: Finished '$*' with status $status ---"
    return $status # Return the original command's exit status
  else
    echo "Running '$*'..."
    # If DEBUG is false, execute the command/function and redirect
    # all standard output (1) and standard error (2) to /dev/null.
    # This effectively suppresses all output.
    "$@" > /dev/null 2>&1
    return $? # Return the original command's exit status
  fi
}

function check_os_version() {
  if [[ $os_release_version_short = "22.04" || $os_release_version_short = "24.04" ]]; then
    return 0
  else
    echo "This script is only compatible with Ubuntu 22.04 and 24.04 server LTS."
    exit 1
  fi
}

function check_root_privileges() {
  if [[ $EUID != 0 ]]; then
    echo "This script must be run with sudo or as the root user."
    exit 1
  fi
}

# --- File Generation Functions --- #

function gen_harbor_yml () {
  [ -f $base_dir/harbor-install-files/harbor/harbor.yml ] || mkdir -p $base_dir/harbor-install-files/harbor
  cat > $base_dir/harbor-install-files/harbor/harbor.yml <<EOF
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
  echo "########################################################################"
  echo "###                 Ubuntu Devapps Harbor Installer                  ###"
  echo "########################################################################"
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
      echo "#######################################"
      echo "###   Harbor Installation Started   ###"
      echo "#######################################"
      install_harbor
      exit 0
      ;;
    uninstall-harbor)
      check_root_privileges
      echo "#########################################"
      echo "###   Harbor Uninstallation Started   ###"
      echo "#########################################"
      uninstall_harbor
      exit 0
      ;;
    offline-prep)
      check_root_privileges
      echo "##############################################"
      echo "###   Harbor Offline Preparation Started   ###"
      echo "##############################################"
      harbor_offline_prep
      exit 0
      ;;
    update-certificates)
      check_root_privileges
      echo "########################################"
      echo "###   Update Certificattes Started   ###"
      echo "########################################"
      update_certificates
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