#!/bin/bash
# A1, on the host that builds the bundle: offline-prep, then hand the archive to the next role.
set -uo pipefail
REPO=$PWD
fail=0
ok()  { echo "PASS  $1"; }
bad() { echo "FAIL  $1"; fail=1; }
# within <seconds> <command...>: true once the command is, checking every 3 seconds
within() { local t=$1 i; shift; for ((i = 0; i < t; i += 3)); do "$@" && return 0; sleep 3; done; "$@"; }
W=$(mktemp -d -p /var/tmp); cd "$W" || exit 1
cp "$REPO/install_harbor.sh" .; chmod +x install_harbor.sh
if ./install_harbor.sh offline-prep > "$W/o" 2>&1 && [ -s harbor-offline-package.tar.gz ]; then
  ok "offline-prep builds harbor-offline-package.tar.gz ($(du -h harbor-offline-package.tar.gz | cut -f1))"
  cp harbor-offline-package.tar.gz "$CI_HANDOFF/" && ok "hand the bundle on" || bad "hand the bundle on"
else
  bad "offline-prep"; tail -8 "$W/o" | cut -c1-170
fi
echo "=== exit $fail"; exit $fail
