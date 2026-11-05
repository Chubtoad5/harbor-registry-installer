#!/usr/bin/env bats
# The air-gap bundle's LICENSES/ folder has to match what the bundle holds.
load ../helpers
setup() {
  load_script install_harbor.sh
  base_dir=$(mktemp -d)
  HARBOR_VERSION=2.15.0
  mkdir -p "$base_dir/harbor-install-files/apt-packages" "$base_dir/pkgs"
  touch "$base_dir/pkgs/iptables_1.8_amd64.deb" "$base_dir/pkgs/curl_8.5_amd64.deb" "$base_dir/pkgs/not-a-package.txt"
  tar -czf "$base_dir/harbor-install-files/apt-packages/offline-packages.tar.gz" -C "$base_dir" pkgs
}
@test "the notice lists the bundle's packages, and doesn't claim there's no GPL" {
  run generate_bundle_licenses
  [ "$status" -eq 0 ]
  n=$base_dir/LICENSES/THIRD_PARTY_NOTICES.txt
  grep -qx 'iptables_1.8_amd64.deb' "$n"
  grep -qx 'curl_8.5_amd64.deb' "$n"
  run grep -c 'not-a-package' "$n"
  [ "$output" = 0 ]
  run grep -ci 'no GPL' "$n"
  [ "$output" = 0 ]
  grep -q 'GPL-2.0-or-later' "$n"
}
@test "there's a written offer, naming the contact" {
  LICENSE_OFFER_CONTACT="someone@example.invalid"
  run generate_bundle_licenses
  [ "$status" -eq 0 ]
  o=$base_dir/LICENSES/WRITTEN_OFFER.txt
  grep -q 'WRITTEN OFFER' "$o"
  grep -q 'contact: someone@example.invalid' "$o"
  grep -q "created ($(date +%Y-%m-%d))" "$o"
}
@test "the contact has a default" {
  [[ "$LICENSE_OFFER_CONTACT" == *Chubtoad5* ]]
}
