#!/usr/bin/env bats
# H1 (the version is recorded only on success), H2 (who was added to the docker group), H6 (empty is not set).
load ../helpers
setup() {
  load_script install_harbor.sh
  setup_stubs
  install_env_file=$(mktemp -d)/.install-env
  HARBOR_VERSION=2.15.0
  user_name=alice
}
@test "H1: a first install records no version until it succeeds" {
  write_install_env
  grep -qx 'HARBOR_VERSION=' "$install_env_file"
  grep -qx 'HARBOR_VERSION_REQUESTED=2.15.0' "$install_env_file"
  commit_install_version
  grep -qx 'HARBOR_VERSION=2.15.0' "$install_env_file"
  grep -qx 'HARBOR_VERSION_REQUESTED=' "$install_env_file"
}
@test "H1: an upgrade keeps the running version recorded until it succeeds" {
  write_install_env; commit_install_version
  HARBOR_VERSION=2.99.0
  write_install_env
  grep -qx 'HARBOR_VERSION=2.15.0' "$install_env_file"
  grep -qx 'HARBOR_VERSION_REQUESTED=2.99.0' "$install_env_file"
}
@test "H1: keys other tools read are still there" {
  REGISTRY_COMMON_NAME=reg.example; HARBOR_PORT=8443
  write_install_env
  grep -qx 'REGISTRY_COMMON_NAME=reg.example' "$install_env_file"
  grep -qx 'HARBOR_PORT=8443' "$install_env_file"
  grep -q '^INSTALL_FILES_DIR=' "$install_env_file"
  grep -q "^INSTALLER_VERSION=$SCRIPT_VERSION$" "$install_env_file"
}
@test "H2: a re-run keeps the record of who was added" {
  write_install_env
  record_docker_group_user alice
  write_install_env
  [ "$(docker_group_users)" = "alice" ]
}
@test "H2: a second user adds to the list, once" {
  write_install_env
  record_docker_group_user alice
  record_docker_group_user bob
  record_docker_group_user alice
  [ "$(docker_group_users)" = "alice bob" ]
}
@test "H2: an older record is still read, and survives a re-run" {
  printf 'INSTALL_USER=carol\nDOCKER_GROUP_ADDED=1\n' > "$install_env_file"
  [ "$(docker_group_users)" = "carol" ]
  write_install_env
  [ "$(docker_group_users)" = "carol" ]
}
@test "H2: an older record with the flag off means nobody" {
  printf 'INSTALL_USER=carol\nDOCKER_GROUP_ADDED=0\n' > "$install_env_file"
  [ -z "$(docker_group_users)" ]
}
flag() { # flag <var> <value or UNSET> <user_set variable>
  if [ "$2" = UNSET ]; then
    env -u "$1" bash -c "source '$BATS_TEST_DIRNAME/../../install_harbor.sh'; echo \"[\$$3]\""
  else
    env "$1=$2" bash -c "source '$BATS_TEST_DIRNAME/../../install_harbor.sh'; echo \"[\$$3]\""
  fi
}
@test "H6: empty counts as not set, for all five variables" {
  while read -r var flagname; do
    [ "$(flag "$var" "" "$flagname")" = "[]" ]
    [ "$(flag "$var" UNSET "$flagname")" = "[]" ]
    [ "$(flag "$var" something "$flagname")" = "[x]" ]
  done <<'T'
REGISTRY_COMMON_NAME user_set_registry_common_name
HARBOR_PORT user_set_harbor_port
HARBOR_VERSION user_set_harbor_version
HARBOR_PASSWORD user_set_harbor_password
HARBOR_DB_PASSWORD user_set_harbor_db_password
T
}
@test "H6: an empty port takes the recorded value" {
  run env HARBOR_PORT= REGISTRY_COMMON_NAME= bash -c "
    source '$BATS_TEST_DIRNAME/../../install_harbor.sh'
    install_env_file=$install_env_file
    printf 'REGISTRY_COMMON_NAME=rec.example\nHARBOR_PORT=8443\n' > \$install_env_file
    load_install_env >/dev/null
    echo \"\$REGISTRY_COMMON_NAME \$HARBOR_PORT\""
  [ "$output" = "rec.example 8443" ]
}
