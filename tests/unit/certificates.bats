#!/usr/bin/env bats
# H3 (an expired CA stops the run, and a leaf can't outlive its CA), and the reuse rule from H10.
load ../helpers
setup() {
  load_script install_harbor.sh
  certs_dir=$(mktemp -d)
  REGISTRY_COMMON_NAME=reg.example; current_hostname=hosty; mgmt_ip=10.0.0.5
  COUNTRY=US; STATE=MA; LOCATION=BOSTON; ORGANIZATION=SELF; DURATION_DAYS=3650
}
make_ca() { # make_ca <days> [faketime offset]
  openssl genrsa -out "$certs_dir/ca.key" 2048 2>/dev/null
  if [ -n "${2:-}" ]; then
    faketime -f "$2" openssl req -x509 -new -nodes -days "$1" -subj "/CN=$REGISTRY_COMMON_NAME" -key "$certs_dir/ca.key" -out "$certs_dir/ca.crt"
  else
    openssl req -x509 -new -nodes -days "$1" -subj "/CN=$REGISTRY_COMMON_NAME" -key "$certs_dir/ca.key" -out "$certs_dir/ca.crt"
  fi
}
@test "H3: no CA yet is fine" {
  check_existing_ca
}
@test "H3: an expired CA stops the run" {
  make_ca 1 '-3d'
  run check_existing_ca
  [ "$status" -eq 1 ]
  [[ "$output" == *"has expired"* && "$output" == *"ROTATE_CA=true"* ]]
}
@test "H3: ROTATE_CA moves an expired CA aside, and ca_gen makes a new one" {
  make_ca 1 '-3d'
  old=$(openssl x509 -noout -fingerprint -in "$certs_dir/ca.crt")
  ROTATE_CA=true
  run check_existing_ca
  [ "$status" -eq 0 ]
  [[ "$output" == *"Every client must trust the new one"* ]]
  [ ! -e "$certs_dir/ca.crt" ]
  compgen -G "$certs_dir/ca.crt.old-*" >/dev/null
  ca_gen >/dev/null
  [ "$(openssl x509 -noout -fingerprint -in "$certs_dir/ca.crt")" != "$old" ]
}
@test "H3: a CA close to expiry warns, and doesn't stop" {
  make_ca 10
  run check_existing_ca
  [ "$status" -eq 0 ]
  [[ "$output" == *"WARNING"* ]]
}
@test "H3: a healthy CA says nothing" {
  make_ca 365
  run check_existing_ca
  [ "$status" -eq 0 ]
  [ -z "$output" ]
}
@test "H3: a server certificate is limited to what the CA has left" {
  make_ca 30
  DURATION_DAYS=365
  run server_cert_gen
  [ "$status" -eq 0 ]
  [[ "$output" == *"WARNING"* ]]
  ca_end=$(date -d "$(openssl x509 -noout -enddate -in "$certs_dir/ca.crt" | cut -d= -f2)" +%s)
  leaf_end=$(date -d "$(openssl x509 -noout -enddate -in "$certs_dir/reg.example.crt" | cut -d= -f2)" +%s)
  [ "$leaf_end" -le "$ca_end" ]
}
@test "H3: a first install doesn't warn about its own new CA" {
  ca_gen >/dev/null
  run server_cert_gen
  [ "$status" -eq 0 ]
  [[ "$output" != *"WARNING"* ]]
}
good_cert() { ca_gen >/dev/null; server_cert_gen >/dev/null; }
@test "H10: a good certificate is reusable" {
  good_cert
  server_cert_reusable
}
@test "H10: a changed name, hostname, address or subject isn't" {
  good_cert
  REGISTRY_COMMON_NAME=other.example; ! server_cert_reusable; REGISTRY_COMMON_NAME=reg.example
  current_hostname=elsewhere; ! server_cert_reusable; current_hostname=hosty
  mgmt_ip=10.0.0.6; ! server_cert_reusable; mgmt_ip=10.0.0.5
  ORGANIZATION=OTHER; ! server_cert_reusable; ORGANIZATION=SELF
  server_cert_reusable
}
@test "H10: one close to expiry isn't" {
  ca_gen >/dev/null
  DURATION_DAYS=10
  server_cert_gen >/dev/null
  ! server_cert_reusable
}
@test "H10: one from another CA isn't" {
  good_cert
  openssl genrsa -out "$certs_dir/ca.key" 2048 2>/dev/null
  openssl req -x509 -new -nodes -days 100 -subj "/CN=new" -key "$certs_dir/ca.key" -out "$certs_dir/ca.crt"
  ! server_cert_reusable
}
@test "H10: cert_gen keeps a good key, and new_cert_check always issues a new one" {
  good_cert
  before=$(sha256sum "$certs_dir/reg.example.key")
  cert_gen >/dev/null
  [ "$(sha256sum "$certs_dir/reg.example.key")" = "$before" ]
  NEW_CERT_GEN=1
  new_cert_check >/dev/null
  [ "$(sha256sum "$certs_dir/reg.example.key")" != "$before" ]
}
@test "H4: a verification failure is caught even when the fingerprint would match" {
  good_cert
  openssl genrsa -out "$certs_dir/ca.key" 2048 2>/dev/null
  openssl req -x509 -new -nodes -days 100 -subj "/CN=new" -key "$certs_dir/ca.key" -out "$certs_dir/ca.crt"
  run verify_served_certificate
  [ "$status" -eq 1 ]
  [[ "$output" == *"doesn't verify"* ]]
}
