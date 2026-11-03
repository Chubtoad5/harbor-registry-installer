#!/usr/bin/env bats
# What ap-tools and the blueprints rely on: subcommands, settings, the state file's keys, and the bundle's name.
load ../helpers
SCRIPT="$BATS_TEST_DIRNAME/../../install_harbor.sh"
@test "version needs no root, and prints a version" {
  run su -s /bin/bash nobody -c "bash '$SCRIPT' version"
  [ "$status" -eq 0 ]
  [[ "$output" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]
  run su -s /bin/bash nobody -c "bash '$SCRIPT' --version"
  [ "$status" -eq 0 ]
}
@test "help lists the subcommands consumers call" {
  run "$SCRIPT" help
  [ "$status" -eq 0 ]
  for sub in install-harbor uninstall-harbor offline-prep update-certificates; do
    [[ "$output" == *"$sub"* ]]
  done
}
@test "an unknown subcommand is an error" {
  run "$SCRIPT" nope
  [ "$status" -ne 0 ]
}
@test "install needs root" {
  run su -s /bin/bash nobody -c "bash '$SCRIPT' install-harbor"
  [ "$status" -ne 0 ]
  [[ "$output" == *"root"* ]]
}
@test "every setting ap-tools forwards is still read" {
  for v in PROJECTS HARBOR_VERSION HARBOR_PORT HARBOR_USERNAME HARBOR_PASSWORD COUNTRY STATE LOCATION ORGANIZATION DURATION_DAYS REGISTRY_COMMON_NAME DEBUG PURGE_DATA; do
    grep -q "^$v=\${$v:-" "$SCRIPT"
  done
}
@test "the state file keeps the keys ap-tools and uninstall read" {
  for k in REGISTRY_COMMON_NAME HARBOR_PORT HARBOR_VERSION INSTALL_USER INSTALL_FILES_DIR CA_FINGERPRINT; do
    grep -q "^$k=" "$SCRIPT"
  done
}
@test "the bundle's name and sentinel stay the same" {
  grep -q 'harbor-offline-package.tar.gz' "$SCRIPT"
  grep -q 'harbor-install-files/VERSION.txt' "$SCRIPT"
}
@test "helper contract: install_packages.sh modes and flags" {
  [ -n "${HELPER_DIR:-}" ] || skip "only in the nightly drift run"
  run bash "$HELPER_DIR/install-packages/install_packages.sh" --version
  [ "$status" -eq 0 ]
  grep -q -- '--no-upgrade' "$HELPER_DIR/install-packages/install_packages.sh"
}
