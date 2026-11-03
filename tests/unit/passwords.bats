#!/usr/bin/env bats
# H5 (the database password) and H7 (special characters), through YAML, curl's config format and the read-back.
load ../helpers
setup() {
  load_script install_harbor.sh
  setup_stubs
  YML=$(mktemp)
  REGISTRY_COMMON_NAME=reg.example; HARBOR_PORT=443; HARBOR_VERSION=2.15.0
}
yaml_value() { python3 -I -c 'import sys,yaml; d=yaml.safe_load(open(sys.argv[1])); print(d["harbor_admin_password"] if sys.argv[2]=="admin" else d["database"]["password"], end="")' "$1" "$2"; }
PASSWORDS=('Abc$123def' 'Abc"123def' 'Abc\123def' 'Abc #123def' 'Abc: 123def' "Abc'123def" 'Abc`123def' 'a\"b\\c"' 'plainPass1' '*star' '!bang' '%pct' '@at' '{x}' '[y]')
@test "H7: every password survives harbor.yml exactly, as YAML sees it" {
  for pw in "${PASSWORDS[@]}"; do
    HARBOR_PASSWORD=$pw; HARBOR_DB_PASSWORD=$pw
    gen_harbor_yml "$YML"
    [ "$(yaml_value "$YML" admin)" = "$pw" ]
    [ "$(yaml_value "$YML" db)" = "$pw" ]
  done
}
@test "H7: every password reads back exactly" {
  for pw in "${PASSWORDS[@]}"; do
    HARBOR_PASSWORD=$pw; HARBOR_DB_PASSWORD=$pw
    gen_harbor_yml "$YML"
    [ "$(yml_password admin "$YML")" = "$pw" ]
    [ "$(yml_password db "$YML")" = "$pw" ]
  done
}
@test "H7: an unquoted database line from an older install still reads" {
  printf 'harbor_admin_password: "Old1pass"\n\ndatabase:\n  password: root123\n  max_idle_conns: 100\n\ndata_volume: /data\n' > "$YML"
  [ "$(yml_password db "$YML")" = "root123" ]
  [ "$(yml_password admin "$YML")" = "Old1pass" ]
}
@test "H7: the database read-back doesn't pick up another section's password" {
  printf 'database:\n  password: "right"\n\nother:\n  password: "wrong"\n' > "$YML"
  [ "$(yml_password db "$YML")" = "right" ]
}
@test "H7: curl's config format sends every password exactly" {
  srv=$(mktemp); log=$(mktemp); cfg=$(mktemp)
  cat > "$srv" <<'PY'
import base64, http.server, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        value = self.headers.get("Authorization", "").split(" ", 1)[-1]
        with open(sys.argv[1], "w") as out: out.write(base64.b64decode(value).decode())
        self.send_response(200); self.end_headers()
    def log_message(self, *a): pass
s = http.server.HTTPServer(("127.0.0.1", 0), H)
with open(sys.argv[1] + ".port", "w") as out: out.write(str(s.server_port))
while True: s.handle_request()
PY
  python3 -I "$srv" "$log" &
  pid=$!
  for _ in 1 2 3 4 5 6 7 8 9 10; do [ -s "$log.port" ] && break; sleep 0.2; done
  port=$(cat "$log.port")
  for pw in "${PASSWORDS[@]}"; do
    write_api_cfg "$cfg" admin "$pw"
    curl -s -K "$cfg" "http://127.0.0.1:$port/" >/dev/null
    [ "$(cat "$log")" = "admin:$pw" ]
  done
  kill "$pid"
}
@test "H7: the credentials file is private" {
  cfg=$(mktemp -u)
  write_api_cfg "$cfg" admin secret
  [ "$(stat -c %a "$cfg")" = "600" ]
}
@test "H7: control characters are refused" {
  HARBOR_PASSWORD=$'bad\tpass'; HARBOR_DB_PASSWORD=ok
  run check_passwords
  [ "$status" -eq 1 ]
  HARBOR_PASSWORD=good; HARBOR_DB_PASSWORD=$'bad\npass'
  run check_passwords
  [ "$status" -eq 1 ]
  HARBOR_PASSWORD=good; HARBOR_DB_PASSWORD=fine
  check_passwords
}
yml_at_opt() { mkdir -p /opt/harbor; printf '%s' "$1" > /opt/harbor/harbor.yml; }
teardown() { rm -f /opt/harbor/harbor.yml; }
@test "H5: a re-run keeps the database password from harbor.yml" {
  yml_at_opt $'database:\n  password: "CustomDb1"\n'
  user_set_harbor_db_password=""; HARBOR_DB_PASSWORD=root123
  preserve_existing_yml_passwords
  [ "$HARBOR_DB_PASSWORD" = "CustomDb1" ]
}
@test "H5: passing the same password is fine, and a different one is refused" {
  yml_at_opt $'database:\n  password: "CustomDb1"\n'
  user_set_harbor_db_password=x; HARBOR_DB_PASSWORD=CustomDb1
  check_existing_db_password
  HARBOR_DB_PASSWORD=Other2
  run check_existing_db_password
  [ "$status" -eq 1 ]
  [[ "$output" == *"differs"* ]]
}
@test "H5: no value passed is fine while harbor.yml exists" {
  yml_at_opt $'database:\n  password: "CustomDb1"\n'
  user_set_harbor_db_password=""
  check_existing_db_password
}
@test "H5: data with no harbor.yml and no value refuses, rather than writing the default" {
  rm -f /opt/harbor/harbor.yml
  user_set_harbor_db_password=""
  run check_existing_db_password
  [ "$status" -eq 1 ]
  [[ "$output" == *"unknown"* ]]
  user_set_harbor_db_password=x
  check_existing_db_password
}
