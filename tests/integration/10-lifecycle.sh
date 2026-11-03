#!/bin/bash
# The real installer on a throwaway host, as root, from the repo root. Runs the failure cases from the spec, and checks
# that what used to go wrong now doesn't. CI_HARBOR_OLD is the version to start from.
set -uo pipefail
REPO=$PWD
export CN=registry.test.lab
OLD=${CI_HARBOR_OLD:-2.14.1}
NEW=2.15.0
fail=0
ok()  { echo "PASS  $1"; }
bad() { echo "FAIL  $1"; fail=1; }
apt-get update -qq >/dev/null 2>&1; DEBIAN_FRONTEND=noninteractive apt-get install -y -qq faketime jq >/dev/null 2>&1
IP=$(hostname -I | awk '{print $1}')
echo "$IP $CN" >> /etc/hosts
W=$(mktemp -d); cd "$W" || exit 1
cp "$REPO/install_harbor.sh" .; chmod +x install_harbor.sh
TGZ=$(mktemp -d)
for v in "$OLD" "$NEW"; do curl -fsSL -o "$TGZ/$v.tgz" "https://github.com/goharbor/harbor/releases/download/v$v/harbor-offline-installer-v$v.tgz" || bad "download $v"; done
stage() { mkdir -p harbor-install-files; [ -s "harbor-install-files/harbor-offline-installer-v$1.tgz" ] || cp "$TGZ/$1.tgz" "harbor-install-files/harbor-offline-installer-v$1.tgz"; }
inst() { env REGISTRY_COMMON_NAME=$CN "$@" ./install_harbor.sh install-harbor >"$W/o" 2>&1; }
wipe() { ./install_harbor.sh uninstall-harbor >/dev/null 2>&1; }
ping_code() { curl -sk -m 5 -o /dev/null -w '%{http_code}' "https://$CN:443/api/v2.0/ping"; }
wait_api() { for _ in $(seq 1 60); do [ "$(ping_code)" = 200 ] && return 0; sleep 5; done; return 1; }
api() { curl -sk -m 10 -K <(printf 'user = "%s:%s"\n' "${U:-admin}" "${PW:-Harbor12345}") "https://$CN:${PORT:-443}/api/v2.0/$1"; }
keyhash() { sha256sum "/opt/harbor/certs/$CN.key" | cut -c1-16; }
started() { docker inspect -f '{{.State.StartedAt}}' harbor-core nginx | tr '\n' ' '; }
dockerts() { systemctl show docker -p ActiveEnterTimestamp --value; }
env_value() { sed -n "s/^$1=//p" /opt/harbor/.install-env; }
tail_o() { tail -4 "$W/o" | cut -c1-170; }

useradd -m -s /bin/bash cisudo 2>/dev/null
echo "=== first install, and an upgrade with data"
stage "$OLD"
if env SUDO_USER=cisudo REGISTRY_COMMON_NAME=$CN HARBOR_VERSION="$OLD" PROJECTS=demo ./install_harbor.sh install-harbor >"$W/o" 2>&1; then ok "install $OLD"; else bad "install $OLD"; tail_o; fi
[ "$(env_value HARBOR_VERSION)" = "$OLD" ] && ok "H1: version recorded after success" || bad "H1: recorded $(env_value HARBOR_VERSION)"
[ "$(env_value DOCKER_GROUP_USERS)" = "cisudo" ] && ok "H2: group user recorded" || bad "H2: recorded '$(env_value DOCKER_GROUP_USERS)'"
wait_api; docker login "$CN:443" -u admin -p Harbor12345 >/dev/null 2>&1 && ok "docker login right after install, with no Docker restart" || bad "docker login failed"
docker pull -q alpine:3.20 >/dev/null; docker tag alpine:3.20 "$CN:443/demo/alpine:3.20"; docker push -q "$CN:443/demo/alpine:3.20" >/dev/null && ok "pushed an image" || bad "push failed"
K=$(keyhash); C=$(sha256sum /opt/harbor/certs/ca.key | cut -c1-16); D=$(dockerts)
stage "$NEW"
if env SUDO_USER=cisudo REGISTRY_COMMON_NAME=$CN HARBOR_VERSION="$NEW" PROJECTS=demo ./install_harbor.sh install-harbor >"$W/o" 2>&1; then ok "upgrade to $NEW"; else bad "upgrade to $NEW"; tail_o; fi
wait_api
api systeminfo | jq -r .harbor_version | grep -q "v$NEW" && ok "H0: running $NEW" || bad "H0: running $(api systeminfo | jq -r .harbor_version)"
docker rmi -f "$CN:443/demo/alpine:3.20" >/dev/null 2>&1; docker pull -q "$CN:443/demo/alpine:3.20" >/dev/null && ok "H0: the image survived" || bad "H0: the image is gone"
[ "$K" = "$(keyhash)" ] && ok "H10: the upgrade kept the server key" || bad "H10: the upgrade replaced the server key"
[ "$C" = "$(sha256sum /opt/harbor/certs/ca.key | cut -c1-16)" ] && ok "the upgrade kept the CA" || bad "the upgrade replaced the CA"
[ "$D" = "$(dockerts)" ] && ok "H10: the upgrade didn't restart Docker" || bad "H10: the upgrade restarted Docker"
[ "$(env_value HARBOR_VERSION)" = "$NEW" ] && ok "H1: new version recorded after success" || bad "H1: recorded $(env_value HARBOR_VERSION)"
[ "$(env_value DOCKER_GROUP_USERS)" = "cisudo" ] && ok "H2: a re-run kept the group user" || bad "H2: now '$(env_value DOCKER_GROUP_USERS)'"

echo "=== H10: an unchanged re-run"
K=$(keyhash); S=$(started); D=$(dockerts)
if env SUDO_USER=cisudo REGISTRY_COMMON_NAME=$CN HARBOR_VERSION="$NEW" PROJECTS="demo extra" ./install_harbor.sh install-harbor >"$W/o" 2>&1; then ok "re-run exit 0"; else bad "re-run failed"; tail_o; fi
grep -q 'No change: Harbor is running as requested' "$W/o" && ok "it says nothing changed" || bad "it didn't take the no-change path"
[ "$K" = "$(keyhash)" ] && ok "key kept" || bad "key replaced"
[ "$S" = "$(started)" ] && ok "containers not restarted" || bad "containers restarted"
[ "$D" = "$(dockerts)" ] && ok "Docker not restarted" || bad "Docker restarted"
api projects | jq -r '.[].name' | grep -qx extra && ok "a new project was still added" || bad "the new project wasn't added"
echo "=== H10: a stopped container gets repaired, and HARBOR_FORCE_REDEPLOY forces it"
docker stop harbor-jobservice >/dev/null
inst HARBOR_VERSION="$NEW" PROJECTS=demo && ok "repair run exit 0" || { bad "repair run failed"; tail_o; }
grep -q 'No change' "$W/o" && bad "it skipped the repair" || ok "it took the full path"
wait_api; [ "$(docker inspect -f '{{.State.Running}}' harbor-jobservice)" = true ] && ok "the container is back" || bad "the container is still down"
S=$(started); inst HARBOR_VERSION="$NEW" HARBOR_FORCE_REDEPLOY=true && ok "forced redeploy exit 0" || bad "forced redeploy failed"
[ "$S" != "$(started)" ] && ok "forced redeploy restarted the stack" || bad "forced redeploy did nothing"
wait_api

echo "=== H1: a bad version changes nothing"
K=$(keyhash); S=$(started)
inst HARBOR_VERSION=2.99.0 && bad "a bad version exited 0" || ok "a bad version fails"
[ "$(env_value HARBOR_VERSION)" = "$NEW" ] && ok "the record still says $NEW" || bad "the record says $(env_value HARBOR_VERSION)"
[ "$K" = "$(keyhash)" ] && ok "key untouched" || bad "key replaced"
[ "$S" = "$(started)" ] && ok "stack untouched" || bad "stack restarted"

echo "=== H4: a failing prepare rolls back"
K=$(keyhash); CRT=$(sha256sum "/opt/harbor/certs/$CN.crt" | cut -c1-16)
cp -a /opt/harbor/prepare /opt/harbor/prepare.real; printf '#!/bin/bash\nexit 1\n' > /opt/harbor/prepare
env NEW_CERT_GEN=1 ./install_harbor.sh update-certificates >"$W/o" 2>&1 && bad "update-certificates exited 0" || ok "update-certificates fails"
mv /opt/harbor/prepare.real /opt/harbor/prepare
[ "$(ping_code)" = 200 ] && ok "Harbor is up after the failure" || bad "Harbor is down after the failure: $(ping_code)"
[ "$K" = "$(keyhash)" ] && [ "$CRT" = "$(sha256sum "/opt/harbor/certs/$CN.crt" | cut -c1-16)" ] && ok "the old certificate is back" || bad "the certificate changed"
[ "$(echo | openssl s_client -connect "$IP:443" -servername "$CN" 2>/dev/null | openssl x509 -noout -fingerprint -sha256 | cut -d= -f2)" = "$(openssl x509 -noout -fingerprint -sha256 -in "/opt/harbor/certs/$CN.crt" | cut -d= -f2)" ] && ok "and it's being served" || bad "a different certificate is being served"
ls -d /opt/harbor/.cert-update.* >/dev/null 2>&1 && bad "the snapshot was left behind" || ok "the snapshot was cleaned up"
echo "=== update-certificates still works"
env NEW_CERT_GEN=1 ./install_harbor.sh update-certificates >"$W/o" 2>&1 && ok "a normal renewal works" || { bad "a normal renewal failed"; tail_o; }
[ "$K" != "$(keyhash)" ] && ok "a renewal does issue a new key" || bad "the renewal kept the old key"
wait_api; docker login "$CN:443" -u admin -p Harbor12345 >/dev/null 2>&1 && ok "docker login after a renewal, with no Docker restart" || bad "docker login failed after a renewal"
echo "=== H6: empty values"
env HARBOR_PORT= REGISTRY_COMMON_NAME= HARBOR_DB_PASSWORD= NEW_CERT_GEN=1 ./install_harbor.sh update-certificates >"$W/o" 2>&1 && ok "update-certificates with empties" || { bad "update-certificates with empties failed"; tail_o; }
grep -q "^hostname: $CN" /opt/harbor/harbor.yml && ok "kept the recorded name" || bad "name is $(grep ^hostname /opt/harbor/harbor.yml)"
wait_api

echo "=== H3: an expired CA"
openssl genrsa -out "$W/exp.key" 2048 2>/dev/null; faketime -f '-3d' openssl req -x509 -new -nodes -days 1 -subj "/CN=$CN" -key "$W/exp.key" -out "$W/exp.crt"
cp /opt/harbor/certs/ca.crt "$W/good.crt"; cp /opt/harbor/certs/ca.key "$W/good.key"
cp "$W/exp.crt" /opt/harbor/certs/ca.crt; cp "$W/exp.key" /opt/harbor/certs/ca.key
K=$(keyhash); S=$(started)
env NEW_CERT_GEN=1 ./install_harbor.sh update-certificates >"$W/o" 2>&1 && bad "update-certificates accepted an expired CA" || ok "update-certificates refuses an expired CA"
grep -q 'has expired' "$W/o" && ok "it says why" || bad "no reason given"
[ "$K" = "$(keyhash)" ] && [ "$S" = "$(started)" ] && ok "nothing changed" || bad "something changed"
inst HARBOR_VERSION="$NEW" && bad "install accepted an expired CA" || ok "install refuses an expired CA"
if env ROTATE_CA=true NEW_CERT_GEN=1 ./install_harbor.sh update-certificates >"$W/o" 2>&1; then ok "ROTATE_CA renews"; else bad "ROTATE_CA failed"; tail_o; fi
openssl verify -CAfile /opt/harbor/certs/ca.crt "/opt/harbor/certs/$CN.crt" >/dev/null 2>&1 && ok "the new chain verifies" || bad "the new chain doesn't verify"
wait_api; docker login "$CN:443" -u admin -p Harbor12345 >/dev/null 2>&1 && ok "docker login with the new CA" || bad "docker login failed with the new CA"
wipe
id -nG cisudo | tr ' ' '\n' | grep -qx docker && bad "H2: uninstall kept the group membership" || ok "H2: uninstall removed the group membership"
stage "$NEW"

echo "=== H3: a certificate can't outlive its CA"
inst DURATION_DAYS=30 && ok "install with 30 days" || { bad "install failed"; tail_o; }
wait_api; env DURATION_DAYS=365 NEW_CERT_GEN=1 ./install_harbor.sh update-certificates >"$W/o" 2>&1 && ok "renewal asking for 365" || { bad "renewal failed"; tail_o; }
[ "$(date -d "$(openssl x509 -noout -enddate -in "/opt/harbor/certs/$CN.crt" | cut -d= -f2)" +%s)" -le "$(date -d "$(openssl x509 -noout -enddate -in /opt/harbor/certs/ca.crt | cut -d= -f2)" +%s)" ] && ok "the certificate ends with the CA" || bad "the certificate outlives the CA"
wipe; stage "$NEW"

echo "=== H5: a custom database password"
inst HARBOR_DB_PASSWORD=CustomDb1 && ok "install with a custom DB password" || { bad "install failed"; tail_o; }
wait_api; inst && ok "a bare re-run" || { bad "a bare re-run failed"; tail_o; }
grep -q 'password: "CustomDb1"' /opt/harbor/harbor.yml && ok "harbor.yml kept it" || bad "harbor.yml: $(grep -A1 '^database' /opt/harbor/harbor.yml | tail -1)"
wait_api && api projects >/dev/null && ok "Harbor still works" || bad "Harbor is broken"
inst HARBOR_DB_PASSWORD=Different1 && bad "a different DB password was accepted" || ok "a different DB password is refused"
wipe; stage "$NEW"

echo "=== H7: passwords"
for pw in 'Abc"123def' 'Abc\123def' 'Abc#123def' "Abc'123def" 'Abc: 123def'; do
  echo ">> $pw"
  if inst "HARBOR_PASSWORD=$pw"; then ok "install"; else bad "install with $pw"; tail_o; fi
  wait_api
  printf '%s' "$pw" | docker login "$CN:443" -u admin --password-stdin >/dev/null 2>&1 && ok "docker login" || bad "docker login with $pw"
  env NEW_CERT_GEN=1 ./install_harbor.sh update-certificates >"$W/o" 2>&1 && ok "update-certificates reads it back" || { bad "update-certificates with $pw"; tail_o; }
  wipe; stage "$NEW"
done
echo ">> a dollar sign"
pw='Abc$123def'
if inst "HARBOR_PASSWORD=$pw"; then ok "install with a dollar sign"; else echo "note: install with a dollar sign failed"; tail_o; fi
wait_api; printf '%s' "$pw" | docker login "$CN:443" -u admin --password-stdin >/dev/null 2>&1 && ok "docker login with a dollar sign" || echo "note: docker login with a dollar sign failed"
wipe; stage "$NEW"

echo "=== H11: HARBOR_USERNAME"
inst HARBOR_USERNAME=ops HARBOR_PASSWORD=changeme && bad "a weak password was accepted" || ok "a weak password is refused"
[ -e /opt/harbor/.install-env ] && bad "the refusal changed something" || ok "the refusal changed nothing"
if inst HARBOR_USERNAME=ops PROJECTS=opsproj; then ok "install as ops"; else bad "install as ops"; tail_o; fi
grep -q 'Administrator: ops' "$W/o" && ok "the banner names it" || bad "the banner doesn't name it"
wait_api; U=ops api users/current | jq -e '.sysadmin_flag == true' >/dev/null && ok "ops is a system administrator" || bad "ops isn't an administrator"
api users/current | jq -e '.username == "admin"' >/dev/null && ok "admin still works" || bad "admin stopped working"
docker login "$CN:443" -u ops -p Harbor12345 >/dev/null 2>&1 && ok "docker login as ops" || bad "docker login as ops failed"
docker tag alpine:3.20 "$CN:443/opsproj/alpine:3.20"; docker push -q "$CN:443/opsproj/alpine:3.20" >/dev/null && ok "push as ops" || bad "push as ops failed"
inst HARBOR_USERNAME=ops PROJECTS=opsproj && ok "a re-run as ops" || { bad "a re-run as ops failed"; tail_o; }
grep -q 'already exists' "$W/o" && ok "it found the existing user" || bad "it didn't find the user"
wipe

echo "=== H12 and H8: offline-prep, then an install on the same machine, and a bundle with curl"
mkdir -p "$W/o2"; cd "$W/o2" || exit 1
cp "$REPO/install_harbor.sh" .; chmod +x install_harbor.sh
mkdir -p harbor-install-files; cp "$TGZ/$NEW.tgz" "harbor-install-files/harbor-offline-installer-v$NEW.tgz"
env HARBOR_VERSION="$NEW" ./install_harbor.sh offline-prep >"$W/o" 2>&1 && ok "offline-prep" || { bad "offline-prep failed"; tail_o; }
tar -tzf harbor-install-files/apt-packages/offline-packages.tar.gz | grep -qE '/curl_' && ok "H8: the bundle holds curl" || bad "H8: no curl in the bundle"
env REGISTRY_COMMON_NAME=$CN HARBOR_VERSION="$OLD" ./install_harbor.sh install-harbor >"$W/o" 2>&1 && bad "H12: a stale bundle accepted another version" || ok "H12: a stale bundle still refuses another version"
grep -q 'HARBOR_FORCE_ONLINE=true' "$W/o" && ok "H12: the error names the way out" || bad "H12: no hint"
[ -e /opt/harbor/.install-env ] && bad "H12: the refusal changed something" || ok "H12: the refusal changed nothing"
cp "$TGZ/$OLD.tgz" "harbor-install-files/harbor-offline-installer-v$OLD.tgz"
if env HARBOR_FORCE_ONLINE=true REGISTRY_COMMON_NAME=$CN HARBOR_VERSION="$OLD" ./install_harbor.sh install-harbor >"$W/o" 2>&1; then ok "H12: HARBOR_FORCE_ONLINE installs it"; else bad "H12: HARBOR_FORCE_ONLINE failed"; tail_o; fi
./install_harbor.sh uninstall-harbor >/dev/null 2>&1
cd "$W" || exit 1
echo "=== air-gapped: the bundle on a host with no curl and no route out"
mkdir -p "$W/o3"; tar -xzf "$W/o2/harbor-offline-package.tar.gz" -C "$W/o3" 2>/dev/null; cd "$W/o3" || exit 1
mv /usr/bin/curl /usr/bin/curl.off
GW=$(ip route | awk '/default/ {print $3; exit}'); DEV=$(ip route | awk '/default/ {print $5; exit}')
# The clone is reached over the LAN, so only the default route goes
ip route del default
if env REGISTRY_COMMON_NAME=$CN HARBOR_VERSION="$NEW" PROJECTS=airgap ./install_harbor.sh install-harbor >"$W/o" 2>&1; then ok "H8: an air-gapped install, with the bundle's curl"; else bad "H8: air-gapped install failed"; tail_o; fi
ip route add default via "$GW" dev "$DEV"
command -v curl >/dev/null && ok "H8: curl was installed from the bundle" || bad "H8: no curl after the install"
[ -e /usr/bin/curl.off ] && { [ -e /usr/bin/curl ] || mv /usr/bin/curl.off /usr/bin/curl; rm -f /usr/bin/curl.off; }
wait_api; api projects | jq -r '.[].name' | grep -qx airgap && ok "the project exists" || bad "the project is missing"
./install_harbor.sh uninstall-harbor >/dev/null 2>&1
echo "=== exit $fail"
exit $fail
