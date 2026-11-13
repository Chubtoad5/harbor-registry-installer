#!/usr/bin/env bats
# Spec 21: any admin password works (H21), and the database password (H22). Every test password goes through harbor.yml,
# its read-back, and Harbor's API, and the bytes that arrive are compared.
load ../helpers
load ../vectors
setup() {
  load_script install_harbor.sh
  setup_stubs
  load_vectors
  YML=$(mktemp)
  REGISTRY_COMMON_NAME=reg.example; HARBOR_PORT=443; HARBOR_VERSION=2.15.0
  data_dir=$(mktemp -d)
  user_set_harbor_db_password=""
}
# Measured on Harbor 2.15 (spec 21's bench): a ' or a space in the database password breaks Harbor itself
DB_REFUSED_EXAMPLES=("Aa1'xYz9" 'Aa1 xYz9' ' Aa1pass ' "'Aa1pass'")
yaml_value() { python3 -I -c 'import sys,yaml; d=yaml.safe_load(open(sys.argv[1])); print(d["harbor_admin_password"] if sys.argv[2]=="admin" else d["database"]["password"], end="")' "$1" "$2"; }

@test "H21: every test password reads back from harbor.yml exactly, and what Harbor's env file gets is one compose keeps" {
  local n pw
  for n in "${VEC_NAMES[@]}"; do
    pw=${VEC[$n]}; echo "vector: $n"
    HARBOR_PASSWORD=$pw; HARBOR_DB_PASSWORD=root123
    gen_harbor_yml "$YML"
    [ "$(yml_password admin "$YML")" = "$pw" ]
    # prepare copies the YAML value into core's env file unquoted: compose must read it back unchanged
    ! compose_changes "$(yaml_value "$YML" admin)" >/dev/null || false
  done
}
@test "H21: a password compose keeps is written as typed, as before; one it changes is encoded and goes through the API" {
  HARBOR_PASSWORD=Harbor12345; gen_harbor_yml "$YML"
  grep -qx 'harbor_admin_password: "Harbor12345"' "$YML"
  ! admin_via_api "${VEC[full]}" || false
  for n in dollar ends yaml1 quotes2; do admin_via_api "${VEC[$n]}"; done
  HARBOR_PASSWORD=${VEC[dollar]}; gen_harbor_yml "$YML"
  grep -qx "harbor_admin_password: \"b64:$(printf '%s' "${VEC[dollar]}" | base64 -w0)\"" "$YML"
  # A password that starts with b64: is encoded too, so it can't be read back as an encoded one
  admin_via_api 'b64:QWJjMTIzZGVm'
  HARBOR_PASSWORD='b64:QWJjMTIzZGVm'; gen_harbor_yml "$YML"
  [ "$(yml_password admin "$YML")" = 'b64:QWJjMTIzZGVm' ]
}
@test "H21: on a first install, a password that needs the API must meet Harbor's API rule, and the message never shows it" {
  local pw
  HARBOR_DB_PASSWORD=root123
  for pw in 'abc$HOME' ' abcdefg1 ' 'ABC #XYZ9' "'ab1defgh'" 'Aa1$x'; do
    HARBOR_PASSWORD=$pw
    run check_passwords
    [ "$status" -eq 1 ]
    [[ "$output" == *"lowercase letter, an uppercase letter and a digit"* ]]
    [[ "$output" == *"Nothing has been changed"* ]]
    [[ "$output" != *"$pw"* ]]
  done
  for n in dollar ends yaml1 full long; do HARBOR_PASSWORD=${VEC[$n]}; check_passwords; done
  # A password compose keeps needs no rule, as before
  HARBOR_PASSWORD=changeme; check_passwords
}
@test "H21: with existing data the password isn't applied, so the API rule isn't asked for" {
  mkdir -p "$data_dir/database"
  HARBOR_PASSWORD='abc$HOME'; HARBOR_DB_PASSWORD=root123
  check_passwords
}
@test "H21: over 128 characters, or a control character, is refused" {
  HARBOR_DB_PASSWORD=root123
  HARBOR_PASSWORD="${VEC[long]}x"
  run check_passwords
  [ "$status" -eq 1 ]
  [[ "$output" == *"over 128 characters"* ]]
  HARBOR_PASSWORD=$'Aa1\tpass'
  run check_passwords
  [ "$status" -eq 1 ]
}

# A fake Harbor API over HTTPS on 127.0.0.1: users/current answers 200 to admin with its current password, and PUT
# users/1/password records the request body and changes it (Harbor's rule included).
start_fake_harbor() { # start_fake_harbor <admin's first password>
  FAKE=$(mktemp -d)
  openssl req -x509 -newkey rsa:2048 -nodes -days 1 -keyout "$FAKE/k" -out "$FAKE/c" -subj /CN=localhost 2>/dev/null
  printf '%s' "$1" > "$FAKE/pw"
  cat > "$FAKE/srv.py" <<'PY'
import base64, http.server, json, re, ssl, sys
D = sys.argv[1]
def pw(): return open(D + "/pw").read()
class H(http.server.BaseHTTPRequestHandler):
    def auth(self):
        v = self.headers.get("Authorization", "")
        return v.startswith("Basic ") and base64.b64decode(v[6:]).decode() == "admin:" + pw()
    def reply(self, code, body=b"{}"):
        self.send_response(code); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    def do_GET(self):
        if self.path.endswith("/users/current") and self.auth(): self.reply(200, b'{"user_id": 1, "username": "admin"}')
        elif self.path.endswith("/ping"): self.reply(200, b"Pong")
        else: self.reply(401)
    def do_PUT(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        open(D + "/put.json", "wb").write(body)
        d = json.loads(body); n = d["new_password"]
        if not self.auth() or d["old_password"] != pw(): return self.reply(401)
        if not (8 <= len(n) <= 128 and re.search("[a-z]", n) and re.search("[A-Z]", n) and re.search("[0-9]", n)):
            return self.reply(400, b'{"errors":[{"code":"BAD_REQUEST","message":"the password or secret must be 8-128"}]}')
        open(D + "/pw", "w").write(n); self.reply(200)
    def log_message(self, *a): pass
s = http.server.HTTPServer(("127.0.0.1", 0), H)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(D + "/c", D + "/k")
s.socket = ctx.wrap_socket(s.socket, server_side=True)
open(D + "/port", "w").write(str(s.server_port))
s.serve_forever()
PY
  python3 -I "$FAKE/srv.py" "$FAKE" &
  FAKE_PID=$!
  for _ in $(seq 1 50); do [ -s "$FAKE/port" ] && break; sleep 0.1; done
  mgmt_ip=127.0.0.1; HARBOR_PORT=$(cat "$FAKE/port"); HARBOR_API_WAIT_SEC=10
  stub sleep 'exit 0'
}
teardown() { [ -n "${FAKE_PID:-}" ] && kill "$FAKE_PID" 2>/dev/null; return 0; }

@test "H21: apply_admin_password sets each test password through the API, exactly, and checks it logs in" {
  local n pw tried=0
  for n in "${VEC_NAMES[@]}"; do
    pw=${VEC[$n]}
    HARBOR_PASSWORD=$pw
    admin_via_api "$pw" || continue
    meets_api_rule "$pw" || continue
    echo "vector: $n"
    start_fake_harbor "$(yml_admin_value)"
    data_preexisting=0
    run apply_admin_password
    echo "$output"
    [ "$status" -eq 0 ]
    [[ "$output" == *"Set admin's password through Harbor's API"* ]]
    [ "$(cat "$FAKE/pw")" = "$pw" ]
    [ "$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["new_password"], end="")' "$FAKE/put.json")" = "$pw" ]
    [[ "$output" != *"$pw"* ]]
    kill "$FAKE_PID"; FAKE_PID=""
    tried=$((tried + 1))
  done
  # dollar, ends, yaml1 and the rest of those that go through the API
  [ "$tried" -ge 4 ]
}
@test "H21: a retry finds the password already set and changes nothing; a password compose keeps never calls the API" {
  HARBOR_PASSWORD=${VEC[dollar]}
  start_fake_harbor "$HARBOR_PASSWORD"
  run apply_admin_password
  [ "$status" -eq 0 ]
  [[ "$output" == *"is the one passed"* ]]
  [ ! -e "$FAKE/put.json" ]
  HARBOR_PASSWORD=Harbor12345
  run apply_admin_password
  [ "$status" -eq 0 ]
  [ -z "$output" ]
}
@test "H21: with existing data, admin keeps its password and the step doesn't fail; a first install that can't log in fails" {
  HARBOR_PASSWORD=${VEC[dollar]}
  start_fake_harbor 'Some-Other-Pass1'
  data_preexisting=1
  run apply_admin_password
  [ "$status" -eq 0 ]
  [ ! -e "$FAKE/put.json" ]
  data_preexisting=0
  run apply_admin_password
  [ "$status" -eq 1 ]
  [[ "$output" == *"CRITICAL"* ]]
}

@test "H22: every test password Harbor takes reads back from harbor.yml exactly, and env files get a form compose keeps" {
  local n pw
  for n in "${VEC_NAMES[@]}"; do
    pw=${VEC[$n]}
    db_password_refused "$pw" && continue
    echo "vector: $n"
    HARBOR_PASSWORD=Harbor12345; HARBOR_DB_PASSWORD=$pw
    gen_harbor_yml "$YML"
    [ "$(yml_password db "$YML")" = "$pw" ]
    v=$(yaml_value "$YML" db)
    if compose_changes "$pw" >/dev/null; then [ "$v" = "$(compose_dq "$pw")" ]; else [ "$v" = "$pw" ]; fi
  done
}
@test "H22: a database password Harbor can't take is refused before anything changes, and one not passed isn't checked" {
  user_set_harbor_db_password=x; HARBOR_PASSWORD=Harbor12345
  for pw in "${DB_REFUSED_EXAMPLES[@]}"; do
    HARBOR_DB_PASSWORD=$pw
    run check_passwords
    [ "$status" -eq 1 ]
    [[ "$output" == *"Harbor itself can't take them"* ]]
    [[ "$output" != *"$pw"* ]]
  done
  HARBOR_DB_PASSWORD="${VEC[long]}x"
  run check_passwords
  [ "$status" -eq 1 ]
  user_set_harbor_db_password=""
  HARBOR_DB_PASSWORD=${DB_REFUSED_EXAMPLES[0]}
  check_passwords
}
@test "H22: a generated database password is 32 letters and digits, and differs each time" {
  a=$(generate_db_password); b=$(generate_db_password)
  [[ "$a" =~ ^[A-Za-z0-9]{32}$ ]]
  [ "$a" != "$b" ]
}
@test "H22: an existing install's database line is written back byte for byte, however it was written" {
  local line
  for line in 'root123' '"CustomDb1"' 'Old #pass' '"Aa1\\$x"'; do
    mkdir -p /opt/harbor
    printf 'harbor_admin_password: "x"\ndatabase:\n  password: %s\n  max_idle_conns: 100\n' "$line" > /opt/harbor/harbor.yml
    user_set_harbor_password=x; user_set_harbor_db_password=""
    preserve_existing_yml_passwords
    gen_harbor_yml "$YML"
    [ "$(sed -n '/^database:/,/^[^ #]/{s/^  password: //p}' "$YML")" = "$line" ]
    HARBOR_DB_YML_LINE=""
  done
  rm -f /opt/harbor/harbor.yml
}
