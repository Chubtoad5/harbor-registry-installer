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
@test "H3: ROTATE_CA touches nothing until the certificates are being made" {
  make_ca 1 '-3d'
  ROTATE_CA=true
  run check_existing_ca
  [ "$status" -eq 0 ]
  [[ "$output" == *"Every client must trust the new one"* ]]
  [ -s "$certs_dir/ca.crt" ]
  ! compgen -G "$certs_dir/ca.crt.old-*" >/dev/null
}
@test "H3: without a rotation due, nothing moves" {
  make_ca 365
  rotate_ca_if_due
  [ -s "$certs_dir/ca.crt" ]
}
@test "H3: ROTATE_CA moves an expired CA aside, and a new one gets made" {
  make_ca 1 '-3d'
  old=$(openssl x509 -noout -fingerprint -in "$certs_dir/ca.crt")
  ROTATE_CA=true
  check_existing_ca >/dev/null
  cert_gen >/dev/null
  compgen -G "$certs_dir/ca.crt.old-*" >/dev/null
  compgen -G "$certs_dir/ca.key.old-*" >/dev/null
  openssl verify -CAfile "$certs_dir/ca.crt" "$certs_dir/reg.example.crt" >/dev/null
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
  # Days are whole, and the leaf starts just after the CA does, so it can end a moment later. It mustn't end days later.
  [ "$leaf_end" -le "$((ca_end + 60))" ]
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
cert_days() { echo $(( ($(date -d "$(openssl x509 -noout -enddate -in "$1" | cut -d= -f2)" +%s) - $(date +%s)) / 86400 )); }
@test "H15: a new CA lives CA_DURATION_DAYS, and the server certificate DURATION_DAYS" {
  DURATION_DAYS=365; CA_DURATION_DAYS=3650
  ca_gen >/dev/null
  server_cert_gen >/dev/null
  [ "$(cert_days "$certs_dir/ca.crt")" -ge 3648 ]
  [ "$(cert_days "$certs_dir/ca.crt")" -le 3650 ]
  [ "$(cert_days "$certs_dir/reg.example.crt")" -ge 363 ]
  [ "$(cert_days "$certs_dir/reg.example.crt")" -le 365 ]
}
@test "H15: unset, CA_DURATION_DAYS takes DURATION_DAYS' value" {
  run env -u CA_DURATION_DAYS DURATION_DAYS=400 bash -c 'source "$1"; echo "$CA_DURATION_DAYS"' _ "$BATS_TEST_DIRNAME/../../install_harbor.sh"
  [ "$output" = "400" ]
  run env -u CA_DURATION_DAYS -u DURATION_DAYS bash -c 'source "$1"; echo "$CA_DURATION_DAYS $DURATION_DAYS"' _ "$BATS_TEST_DIRNAME/../../install_harbor.sh"
  [ "$output" = "3650 3650" ]
}
@test "H15: an existing CA keeps its lifetime" {
  make_ca 100
  before=$(sha256sum "$certs_dir/ca.crt")
  CA_DURATION_DAYS=3650
  ca_gen >/dev/null
  [ "$(sha256sum "$certs_dir/ca.crt")" = "$before" ]
}
@test "H15: a CA shorter than its certificate, or a value that isn't a whole number, is refused" {
  DURATION_DAYS=365; CA_DURATION_DAYS=100
  run check_durations
  [ "$status" -eq 1 ]
  [[ "$output" == *"shorter than DURATION_DAYS"* ]]
  for bad in 0 -5 abc 3.5 ""; do
    DURATION_DAYS=365; CA_DURATION_DAYS=$bad
    run check_durations
    [ "$status" -eq 1 ]
    DURATION_DAYS=$bad; CA_DURATION_DAYS=3650
    run check_durations
    [ "$status" -eq 1 ]
  done
  DURATION_DAYS=365; CA_DURATION_DAYS=365
  check_durations
  DURATION_DAYS=365; CA_DURATION_DAYS=3650
  check_durations
}
@test "H15: with a CA kept, a shorter CA_DURATION_DAYS isn't refused, since it doesn't apply" {
  make_ca 100
  DURATION_DAYS=5000; CA_DURATION_DAYS=3650; ROTATE_CA=false
  check_durations
  ROTATE_CA=true
  run check_durations
  [ "$status" -eq 1 ]
}
