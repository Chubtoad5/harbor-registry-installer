#!/usr/bin/env bats
# On EL, the bundle carries the running kernel's kernel-modules-extra, and a bundle install uses it (spec 15, F1).
load ../helpers
KVER=6.12.0-211.16.1.el10_2.0.1.x86_64
setup() {
  load_script install_harbor.sh
  setup_stubs
  stub uname "echo $KVER"
  os_id=rocky
  base_dir=$(mktemp -d)
  A="$base_dir/harbor-install-files/apt-packages"
  mkdir -p "$A"
  printf '#!/bin/bash\necho "install_packages.sh $*" >> "$STUB_LOG"\n' > "$A/install_packages.sh"
  chmod +x "$A/install_packages.sh"
}
bundle_tar() { # bundle_tar <names of fake packages...>: a bundle, in bundle mode
  local d; d=$(mktemp -d); mkdir -p "$d/offline-packages"
  for n in "$@"; do touch "$d/offline-packages/$n"; done
  tar -czf "$A/offline-packages.tar.gz" -C "$d" offline-packages
  touch "$base_dir/harbor-install-files/VERSION.txt"
}
@test "save: on EL, the running kernel's kernel-modules-extra, when the repos have it" {
  stub dnf "echo kernel-modules-extra-0:$KVER"
  run el_modules_extra_pkg
  [ "$output" = "kernel-modules-extra-$KVER" ]
}
@test "save: when the repos no longer have it, nothing, and a note" {
  stub dnf 'exit 0'
  run el_modules_extra_pkg
  [ "$status" -eq 0 ]
  [[ "$output" == *"isn't in this host's repos"* ]]
  [[ "$output" != kernel-modules-extra-* ]]
}
@test "save: off EL, nothing" {
  os_id=ubuntu
  run el_modules_extra_pkg
  [ -z "$output" ]
}
@test "bundle install: a matching package in the bundle is installed from it" {
  stub modprobe 'case "$*" in "-n xt_addrtype") exit 1 ;; *) exit 0 ;; esac'
  bundle_tar docker-ce-29.1.0-1.el10.x86_64.rpm "kernel-modules-extra-$KVER.rpm"
  run ensure_el_kernel_modules
  [ "$status" -eq 0 ]
  called "install_packages.sh offline kernel-modules-extra-$KVER"
  ! called "dnf install"
  [[ "$output" == *"xt_addrtype kernel module loaded"* ]]
}
@test "bundle install: a package for another kernel isn't used, and the message says so" {
  stub modprobe 'case "$*" in "-n xt_addrtype") exit 1 ;; *) exit 0 ;; esac'
  bundle_tar kernel-modules-extra-6.12.0-211.74.1.el10_2.x86_64.rpm
  run ensure_el_kernel_modules
  [ "$status" -eq 1 ]
  ! called "install_packages.sh offline"
  [[ "$output" == *"built on a host running 6.12.0-211.74.1.el10_2.x86_64"* ]]
  [[ "$output" == *"dnf install kernel-modules-extra-$KVER"* ]]
}
@test "online: unchanged, the running kernel's package from the repos" {
  stub modprobe 'case "$*" in "-n xt_addrtype") exit 1 ;; *) exit 0 ;; esac'
  stub dnf 'exit 0'
  run ensure_el_kernel_modules
  [ "$status" -eq 0 ]
  called "dnf install -y kernel-modules-extra-$KVER"
}
