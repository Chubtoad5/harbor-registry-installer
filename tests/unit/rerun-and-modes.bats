#!/usr/bin/env bats
# H8 (curl), H10 (an unchanged re-run), H11 (the username), H12 (bundle mode), and fetching the helper.
load ../helpers
setup() {
  load_script install_harbor.sh
  setup_stubs
  base_dir=$(mktemp -d)
  mkdir -p "$base_dir/harbor-install-files/apt-packages"
  os_id=ubuntu
}
teardown() { rm -f /opt/harbor/harbor.yml /opt/harbor/docker-compose.yml /opt/harbor/.install-env; }
bundle_tar() { # bundle_tar <names of fake packages...>
  local d; d=$(mktemp -d); mkdir -p "$d/offline-packages"
  for n in "$@"; do touch "$d/offline-packages/$n"; done
  tar -czf "$base_dir/harbor-install-files/apt-packages/offline-packages.tar.gz" -C "$d" offline-packages
}
@test "H14: an upgrade removes the old image archive, so upstream's install.sh can load the new one" {
  mkdir -p /opt/harbor "$base_dir/t/harbor"
  touch /opt/harbor/harbor.v2.14.1.tar.gz "$base_dir/t/harbor/harbor.v2.15.0.tar.gz"
  # The same test as upstream's: with two files this is an error, and the load is skipped
  cat > "$base_dir/t/harbor/install.sh" <<'S'
#!/bin/bash
cd /opt/harbor || exit 1
if [ -f harbor*.tar.gz ]; then echo "loading $(ls harbor*.tar.gz)" >> "$STUB_LOG"; fi
S
  chmod +x "$base_dir/t/harbor/install.sh"
  HARBOR_VERSION=2.15.0
  tar -czf "$base_dir/harbor-install-files/harbor-offline-installer-v2.15.0.tgz" -C "$base_dir/t" harbor
  run_harbor_installer >/dev/null 2>&1
  called 'loading harbor.v2.15.0.tar.gz'
  [ ! -e /opt/harbor/harbor.v2.14.1.tar.gz ]
  rm -f /opt/harbor/harbor.v*.tar.gz /opt/harbor/install.sh
}
@test "H12: VERSION.txt selects bundle mode, and HARBOR_FORCE_ONLINE overrides it" {
  ! bundle_mode || false
  touch "$base_dir/harbor-install-files/VERSION.txt"
  bundle_mode
  HARBOR_FORCE_ONLINE=true
  ! bundle_mode || false
}
@test "H12: a missing installer in bundle mode names the way out" {
  touch "$base_dir/harbor-install-files/VERSION.txt"
  HARBOR_VERSION=2.15.0
  run prefetch_harbor_installer
  [ "$status" -eq 1 ]
  [[ "$output" == *"HARBOR_FORCE_ONLINE=true"* ]]
}
no_curl_path() { # a PATH with what preflight needs, and no curl
  local d; d=$(mktemp -d)
  for c in tar openssl grep gzip sed awk cut bash; do ln -s "$(command -v "$c")" "$d/$c"; done
  echo "$d"
}
@test "H8: online, no curl: preflight stops" {
  p=$(no_curl_path)
  PATH=$p run preflight_checks install
  [ "$status" -eq 1 ]
  [[ "$output" == *"curl"* ]]
}
@test "H8: an older bundle with no curl, on a host with none: preflight stops" {
  touch "$base_dir/harbor-install-files/VERSION.txt"
  bundle_tar docker-ce_1_amd64.deb
  p=$(no_curl_path)
  PATH=$p run preflight_checks install
  [ "$status" -eq 1 ]
  [[ "$output" == *"curl"* ]]
}
@test "H8: a bundle that brings curl passes on a host with none" {
  touch "$base_dir/harbor-install-files/VERSION.txt"
  bundle_tar docker-ce_1_amd64.deb curl_8.5.0-2_amd64.deb
  p=$(no_curl_path)
  PATH=$p run preflight_checks install
  [ "$status" -eq 0 ]
}
@test "H8: rpm names count as curl too, and libcurl doesn't" {
  bundle_tar curl-7.76.1-40.el9.x86_64.rpm
  bundle_has_curl
  bundle_tar libcurl4_8.5.0_amd64.deb
  ! bundle_has_curl
}
@test "fetch_helper: fetches, keeps a cached copy for the same ref, refetches for another" {
  src=$(mktemp); echo one > "$src"; d=$(mktemp -d)
  fetch_helper "$d/h.sh" "file://$src" v1
  [ "$(cat "$d/h.sh")" = "one" ]; [ -x "$d/h.sh" ]
  echo two > "$src"
  fetch_helper "$d/h.sh" "file://$src" v1
  [ "$(cat "$d/h.sh")" = "one" ]
  fetch_helper "$d/h.sh" "file://$src" v2
  [ "$(cat "$d/h.sh")" = "two" ]
}
@test "fetch_helper: a cached copy with no record is fetched again" {
  src=$(mktemp); echo new > "$src"; d=$(mktemp -d); echo old > "$d/h.sh"
  fetch_helper "$d/h.sh" "file://$src" v1
  [ "$(cat "$d/h.sh")" = "new" ]
}
@test "fetch_helper: a bad URL or checksum fails, and leaves nothing behind" {
  src=$(mktemp); echo x > "$src"; d=$(mktemp -d)
  run fetch_helper "$d/h.sh" "file:///nonexistent" v1
  [ "$status" -eq 1 ]; [ ! -e "$d/h.sh" ]; [ ! -e "$d/h.sh.tmp" ]
  run fetch_helper "$d/h.sh" "file://$src" v1 0000000000000000000000000000000000000000000000000000000000000000
  [ "$status" -eq 1 ]; [ ! -e "$d/h.sh" ]
  fetch_helper "$d/h.sh" "file://$src" v1 "$(sha256sum "$src" | cut -d' ' -f1)"
  [ -s "$d/h.sh" ]
}
@test "the bundle's own helper is used, and nothing is fetched" {
  touch "$base_dir/harbor-install-files/VERSION.txt"
  echo bundled > "$base_dir/harbor-install-files/apt-packages/install_packages.sh"
  stub curl 'exit 7'
  install_packages_check
  ! called 'curl'
}
@test "the default helper is a tag, not main" {
  [[ "$INSTALL_PACKAGES_URL" == *"/install-packages/v"* ]]
}
no_docker_path() { # a PATH with no docker on it
  local d; d=$(mktemp -d)
  for c in grep sed awk cut; do ln -s "$(command -v "$c")" "$d/$c"; done
  echo "$d"
}
@test "DOCKER_VERSION pins only the engine and the client, on a host with no Docker" {
  DOCKER_VERSION=28.5
  DOCKER_PACKAGES=(docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin)
  old=$PATH; PATH=$(no_docker_path)
  select_docker_packages
  PATH=$old
  [ "${DOCKER_PACKAGES[*]}" = "docker-ce=28.5 docker-ce-cli=28.5 containerd.io docker-buildx-plugin docker-compose-plugin" ]
}
@test "DOCKER_VERSION is ignored when Docker is here, and says so" {
  stub docker 'exit 0'
  DOCKER_VERSION=28.5
  DOCKER_PACKAGES=(docker-ce docker-ce-cli)
  select_docker_packages > "$STUB_DIR/out"
  [ "${DOCKER_PACKAGES[*]}" = "docker-ce docker-ce-cli" ]
  grep -q 'ignored' "$STUB_DIR/out"
}
@test "DOCKER_VERSION still pins a bundle when Docker is here" {
  stub docker 'exit 0'
  DOCKER_VERSION=28.5
  DOCKER_PACKAGES=(docker-ce docker-ce-cli)
  select_docker_packages save
  [ "${DOCKER_PACKAGES[*]}" = "docker-ce=28.5 docker-ce-cli=28.5" ]
}
@test "the host's own curl is left alone, because RHEL 9's curl-minimal conflicts with curl" {
  touch "$base_dir/harbor-install-files/VERSION.txt"
  bundle_tar curl_8.5.0-2_amd64.deb docker-ce_1_amd64.deb
  stub curl 'exit 0'; stub docker 'exit 0'; stub systemctl 'exit 0'; stub usermod 'exit 0'
  cat > "$base_dir/harbor-install-files/apt-packages/install_packages.sh" <<'S'
#!/bin/bash
echo "helper $*" >> "$STUB_LOG"
S
  chmod +x "$base_dir/harbor-install-files/apt-packages/install_packages.sh"
  create_bridge_json() { :; }
  DOCKER_PACKAGES=(docker-ce)
  install_docker_utility >/dev/null
  called 'helper offline'
  ! grep 'helper offline' "$STUB_LOG" | grep -qw curl
}
@test "H11: admin needs no checks" {
  HARBOR_USERNAME=admin; HARBOR_PASSWORD=changeme
  check_harbor_username
}
@test "H11: another name needs a good name and a strong password" {
  HARBOR_USERNAME=ops; HARBOR_PASSWORD=Harbor12345
  check_harbor_username
  HARBOR_PASSWORD=changeme
  run check_harbor_username
  [ "$status" -eq 1 ]; [[ "$output" == *"stronger"* ]]
  HARBOR_PASSWORD=Sh0rt
  run check_harbor_username
  [ "$status" -eq 1 ]
  HARBOR_PASSWORD=Harbor12345; HARBOR_USERNAME='bad name'
  run check_harbor_username
  [ "$status" -eq 1 ]; [[ "$output" == *"letters"* ]]
}
# A fake Harbor API: $CASE decides how it behaves. Logs each request.
fake_api() {
  stub curl 'args="$*"; out=""; while [ $# -gt 0 ]; do case "$1" in -o) out=$2; shift ;; -D) hdr=$2; shift ;; esac; shift; done
    case "$args" in
      *users/current*)
        case "$CASE" in
          exists-admin) body="{\"user_id\": 7, \"sysadmin_flag\": true}"; code=200 ;;
          exists-plain) body="{\"user_id\": 7, \"sysadmin_flag\": false}"; code=200 ;;
          *) body="{}"; code=401 ;;
        esac ;;
      *"-X POST"*users*)
        case "$CASE" in
          clash) code=409 ;;
          refused) code=400 ;;
          *) code=201; [ -n "${hdr:-}" ] && printf "HTTP/1.1 201\r\nLocation: /api/v2.0/users/42\r\n" > "$hdr" ;;
        esac ;;
      *sysadmin*) code=200 ;;
      *) code=200 ;;
    esac
    [ -n "$out" ] && [ "$out" != /dev/null ] && printf "%s" "${body:-}" > "$out"
    printf "%s" "$code"'
}
ensure() { HARBOR_USERNAME=ops; HARBOR_PASSWORD='Harbor1"2'; REGISTRY_COMMON_NAME=reg.example; mgmt_ip=10.0.0.5; HARBOR_PORT=443
  a=$(mktemp); n=$(mktemp); ensure_harbor_user "$a" "$n"; }
@test "H11: a new user gets created and made an administrator" {
  export CASE=new; fake_api
  run ensure
  [ "$status" -eq 0 ]; [[ "$output" == *"Created administrator"* ]]
  called '/users/42/sysadmin'
}
@test "H11: an existing administrator is left alone" {
  export CASE=exists-admin; fake_api
  run ensure
  [ "$status" -eq 0 ]; [[ "$output" == *"already exists"* ]]
  ! called 'sysadmin_flag'
}
@test "H11: an existing plain user is made an administrator" {
  export CASE=exists-plain; fake_api
  run ensure
  [ "$status" -eq 0 ]
  called '/users/7/sysadmin'
}
@test "H11: a user with another password is reported, and nothing changes" {
  export CASE=clash; fake_api
  run ensure
  [ "$status" -eq 1 ]; [[ "$output" == *"different password"* ]]
  ! called 'sysadmin_flag'
}
@test "H11: a refused user is reported" {
  export CASE=refused; fake_api
  run ensure
  [ "$status" -eq 1 ]; [[ "$output" == *"HTTP 400"* ]]
}
unchanged_host() { # a fake install that matches the request
  certs_dir=$(mktemp -d); install_env_file=/opt/harbor/.install-env
  REGISTRY_COMMON_NAME=reg.example; current_hostname=hosty; mgmt_ip=10.0.0.5; HARBOR_PORT=443; HARBOR_VERSION=2.15.0
  HARBOR_PASSWORD=Harbor12345; HARBOR_DB_PASSWORD=root123
  COUNTRY=US; STATE=MA; LOCATION=BOSTON; ORGANIZATION=SELF
  mkdir -p /opt/harbor
  ca_gen >/dev/null; server_cert_gen >/dev/null
  gen_harbor_yml
  touch /opt/harbor/docker-compose.yml
  echo "HARBOR_VERSION=2.15.0" > "$install_env_file"
  export RUNNING=3 TOTAL=3 IMAGE=goharbor/harbor-core:v2.15.0
  stub docker 'case "$*" in
    inspect*) echo "$IMAGE" ;;
    *"--status running"*) seq 1 "$RUNNING" ;;
    *"ps -a"*) seq 1 "$TOTAL" ;;
  esac'
}
@test "H10: nothing changed: unchanged" {
  unchanged_host
  harbor_unchanged
}
@test "H10: a CA rotation that's due isn't unchanged" {
  unchanged_host
  ca_rotation_due=1
  ! harbor_unchanged || false
}
@test "H10: HARBOR_FORCE_REDEPLOY overrides it" {
  unchanged_host
  HARBOR_FORCE_REDEPLOY=true
  ! harbor_unchanged || false
}
@test "H10: a requested version that isn't recorded or running isn't unchanged" {
  unchanged_host
  HARBOR_VERSION=2.16.0
  ! harbor_unchanged || false
  HARBOR_VERSION=2.15.0
  export IMAGE=goharbor/harbor-core:v2.14.1
  ! harbor_unchanged || false
}
@test "H10: a stopped container isn't unchanged, so a re-run repairs it" {
  unchanged_host
  export RUNNING=2
  ! harbor_unchanged || false
}
@test "H10: a changed setting that lands in harbor.yml isn't unchanged" {
  unchanged_host
  HARBOR_PORT=8443
  ! harbor_unchanged || false
}
@test "H10: a manual edit to harbor.yml isn't unchanged" {
  unchanged_host
  echo "# edited" >> /opt/harbor/harbor.yml
  ! harbor_unchanged || false
}
@test "H10: a different admin password alone needs no redeploy" {
  unchanged_host
  HARBOR_PASSWORD=Different1pass
  harbor_unchanged
}
@test "H10: a different database password does" {
  unchanged_host
  HARBOR_DB_PASSWORD=Different1
  ! harbor_unchanged || false
}
@test "H10: a certificate that needs replacing isn't unchanged" {
  unchanged_host
  mgmt_ip=10.0.0.6
  gen_harbor_yml
  ! harbor_unchanged || false
}
proxy() { # proxy <what core says directly> <what comes back through nginx>
  export CORE_BODY=$1 NGINX_BODY=$2
  mgmt_ip=10.0.0.5; HARBOR_PORT=443
  stub docker 'case "$1" in exec) printf "%s" "$CORE_BODY" ;; esac'
  stub curl 'printf "%s" "$NGINX_BODY"'
}
@test "H13: core answers and nginx doesn't: restart nginx" {
  proxy Pong '{"code":10011,"message":"unauthorized"}'
  run heal_stale_proxy
  [ "$status" -eq 0 ]
  [[ "$output" == *"wrong container"* ]]
  called 'docker restart nginx'
}
@test "H13: nginx is fine: leave it alone" {
  proxy Pong Pong
  heal_stale_proxy
  ! called 'docker restart'
}
@test "H13: core isn't up yet: leave nginx alone" {
  proxy '' ''
  heal_stale_proxy
  ! called 'docker restart'
}
@test "H13: wait_for_harbor_api heals, then gives up with a failure" {
  proxy Pong nope
  HARBOR_API_WAIT_SEC=5
  stub sleep 'exit 0'
  run wait_for_harbor_api
  [ "$status" -eq 1 ]
  called 'docker restart nginx'
  proxy Pong Pong
  wait_for_harbor_api
}
downgrade_host() { # downgrade_host <running version or empty> [recorded version]
  install_env_file=$(mktemp)
  export RUNNING_IMAGE=${1:+goharbor/harbor-core:v$1}
  stub docker 'case "$1" in inspect) [ -n "$RUNNING_IMAGE" ] && echo "$RUNNING_IMAGE" || exit 1 ;; esac'
  [ -n "${2:-}" ] && echo "HARBOR_VERSION=$2" > "$install_env_file"
  return 0
}
@test "HC2: an older version is refused, and an upgrade or the same version isn't" {
  downgrade_host 2.15.0
  HARBOR_VERSION=2.14.1
  run check_downgrade
  [ "$status" -eq 1 ]
  [[ "$output" == *"older"* && "$output" == *"HARBOR_ALLOW_DOWNGRADE=true"* ]]
  HARBOR_VERSION=2.15.0; check_downgrade
  HARBOR_VERSION=2.16.0; check_downgrade
}
@test "HC2: versions compare as versions, not as text" {
  downgrade_host 2.9.0
  HARBOR_VERSION=2.10.0; check_downgrade
  downgrade_host 2.10.0
  HARBOR_VERSION=2.9.0
  run check_downgrade
  [ "$status" -eq 1 ]
}
@test "HC2: a stopped stack falls back to the record" {
  downgrade_host "" 2.15.0
  HARBOR_VERSION=2.14.1
  run check_downgrade
  [ "$status" -eq 1 ]
}
@test "HC2: nothing known means nothing to compare" {
  downgrade_host ""
  HARBOR_VERSION=2.14.1
  check_downgrade
}
@test "HC2: HARBOR_ALLOW_DOWNGRADE skips the check" {
  downgrade_host 2.15.0
  HARBOR_VERSION=2.14.1; HARBOR_ALLOW_DOWNGRADE=true
  check_downgrade
}
