#!/bin/bash
# A1, on a clean host with no route out: install from the bundle the build role made, push an image to it, uninstall.
# The test installs nothing of its own: the image it pushes is one of Harbor's own, loaded from the bundle.
set -uo pipefail
fail=0
ok()  { echo "PASS  $1"; }
bad() { echo "FAIL  $1"; fail=1; }
# within <seconds> <command...>: true once the command is, checking every 3 seconds
within() { local t=$1 i; shift; for ((i = 0; i < t; i += 3)); do "$@" && return 0; sleep 3; done; "$@"; }
W=$(mktemp -d -p /var/tmp); cd "$W" || exit 1
CN=reg.test.lab PW=Test-Pass-1
grep -q " $CN\$" /etc/hosts || echo "127.0.0.1 $CN" >> /etc/hosts
tar -xzf "$CI_HANDOFF/harbor-offline-package.tar.gz" && ok "unpack the bundle" || { bad "unpack the bundle"; echo "=== exit 1"; exit 1; }
if env REGISTRY_COMMON_NAME=$CN HARBOR_PASSWORD=$PW ./install_harbor.sh install-harbor > "$W/o" 2>&1; then ok "install with no route out"; else bad "install with no route out"; tail -10 "$W/o" | cut -c1-170; fi
healthy() { [ "$(curl -sk -m 10 "https://$CN/api/v2.0/health" | grep -o '"status":"[a-z]*"' | head -1)" = '"status":"healthy"' ]; }
within 180 healthy && ok "Harbor reports healthy" || bad "Harbor isn't healthy"
c=$(curl -sk -m 10 -o /dev/null -w '%{http_code}' -u "admin:$PW" "https://$CN/api/v2.0/users/current"); [ "$c" = 200 ] && ok "admin logs in" || bad "admin login got $c"
img=$(docker images --format '{{.Repository}}:{{.Tag}}' | grep -m1 '^goharbor/registry-photon:')
# By CN:port, as the installer trusts the CA for (certs.d/<CN>:<port>)
R="$CN:443"
if [ -n "$img" ] && printf '%s' "$PW" | docker login "$R" -u admin --password-stdin > "$W/d" 2>&1 \
   && docker tag "$img" "$R/library/ci-a1:1" && docker push "$R/library/ci-a1:1" >> "$W/d" 2>&1; then
  ok "push an image to it, over TLS, with no route out"
else
  bad "push an image to it ($img)"; tail -4 "$W/d" | cut -c1-170; ls /etc/docker/certs.d/ 2>&1 | head -3
fi
c=$(curl -sk -m 10 -o /dev/null -w '%{http_code}' -u "admin:$PW" "https://$CN/api/v2.0/projects/library/repositories/ci-a1"); [ "$c" = 200 ] && ok "the image is in the registry" || bad "the registry has no ci-a1 ($c)"
./install_harbor.sh uninstall-harbor > "$W/o" 2>&1 && ok "uninstall" || { bad "uninstall"; tail -6 "$W/o" | cut -c1-170; }
echo "=== exit $fail"; exit $fail
