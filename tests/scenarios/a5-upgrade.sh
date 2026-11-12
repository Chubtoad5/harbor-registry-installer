#!/bin/bash
# A5 (spec 21): install the last release (its source archive from GitHub) with a plain admin password, push an image,
# then install the commit under test over it with the same settings, passing no password. Nothing is redeployed or
# restarted, harbor.yml is unchanged byte for byte, and the password and the image still work.
set -uo pipefail
REPO=$PWD
fail=0
ok()  { echo "PASS  $1"; }
bad() { echo "FAIL  $1"; fail=1; }
within() { local t=$1 i; shift; for ((i = 0; i < t; i += 3)); do "$@" && return 0; sleep 3; done; "$@"; }
W=$(mktemp -d -p /var/tmp); cd "$W" || exit 1
R=harbor-registry-installer
old=$(curl -sI -m 20 "https://github.com/Chubtoad5/$R/releases/latest" | tr -d '\r' | sed -n 's#^[Ll]ocation: .*/tag/##p')
[[ "$old" =~ ^v[0-9]+(\.[0-9]+)+$ ]] && ok "the last release is $old" || { bad "couldn't find the last release: '$old'"; echo "=== exit 1"; exit 1; }
mkdir old new
curl -sfL -m 180 "https://github.com/Chubtoad5/$R/archive/refs/tags/$old.tar.gz" | tar -xz -C old --strip-components=1 && [ -x old/install_harbor.sh ] \
  && ok "download $old" || { bad "download $old"; echo "=== exit 1"; exit 1; }
cp "$REPO/install_harbor.sh" new/; chmod +x new/install_harbor.sh
CN=reg.a5.test PW=changeme
grep -q " $CN\$" /etc/hosts || echo "127.0.0.1 $CN" >> /etc/hosts
healthy() { [ "$(curl -sk -m 10 "https://$CN/api/v2.0/health" | grep -o '"status":"[a-z]*"' | head -1)" = '"status":"healthy"' ]; }
login() { [ "$(curl -sk -m 10 -o /dev/null -w '%{http_code}' -K <(printf 'user = "admin:%s"\n' "$PW") "https://$CN/api/v2.0/users/current")" = 200 ]; }
state() { docker ps --format '{{.Names}}' | sort | while read -r c; do docker inspect -f '{{.Name}} {{.Id}} {{.State.StartedAt}}' "$c"; done; }

if (cd old && env REGISTRY_COMMON_NAME=$CN HARBOR_PASSWORD=$PW PROJECTS=a5 ./install_harbor.sh install-harbor) > o1 2>&1; then ok "install $old"
else bad "install $old"; tail -8 o1 | cut -c1-170; echo "=== exit 1"; exit 1; fi
within 180 healthy && ok "$old is healthy" || bad "$old isn't healthy"
img=$(docker images --format '{{.Repository}}:{{.Tag}}' | grep -m1 '^goharbor/registry-photon:')
if printf '%s' "$PW" | docker login "$CN:443" -u admin --password-stdin >/dev/null 2>&1 && docker tag "$img" "$CN:443/a5/ci-a5:1" \
   && docker push -q "$CN:443/a5/ci-a5:1" >/dev/null 2>&1; then ok "push an image to $old"; else bad "push an image to $old"; fi
before=$(state); yml=$(sha256sum < /opt/harbor/harbor.yml)

if (cd new && env REGISTRY_COMMON_NAME=$CN PROJECTS=a5 ./install_harbor.sh install-harbor) > o2 2>&1; then ok "install the commit under test over $old"
else bad "install the commit under test over $old"; tail -10 o2 | cut -c1-170; fi
grep -q 'No change' o2 && ok "it says No change" || bad "it redeployed"
[ "$(state)" = "$before" ] && ok "no container was recreated or restarted" || bad "containers changed: $(diff <(echo "$before") <(state) | grep -c '^[<>]') lines differ"
[ "$(sha256sum < /opt/harbor/harbor.yml)" = "$yml" ] && ok "harbor.yml is unchanged, byte for byte" || bad "harbor.yml changed"
within 60 login && ok "the admin password still works" || bad "the admin password no longer works"
docker rmi -f "$CN:443/a5/ci-a5:1" >/dev/null 2>&1
docker pull -q "$CN:443/a5/ci-a5:1" >/dev/null 2>&1 && ok "the image pushed to $old pulls" || bad "the image pushed to $old doesn't pull"
(cd new && ./install_harbor.sh uninstall-harbor) > o3 2>&1 && ok "uninstall" || { bad "uninstall"; tail -6 o3 | cut -c1-170; }
echo "=== exit $fail"; exit $fail
