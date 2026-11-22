#!/usr/bin/env bats
# v1.5.0 (spec 31): PROJECTS unset or empty creates the projects the Chubtoad5 tools push to; a list, exactly that.
load ../helpers
projects_with() { # projects_with <unset|value>: PROJECTS after the script's two settings lines, in a fresh shell
  local lines; lines=$(grep -E '^(SUITE_PROJECTS|PROJECTS)=' "$BATS_TEST_DIRNAME/../../install_harbor.sh")
  if [[ "$1" == unset ]]; then
    ( unset PROJECTS; eval "$lines"; printf '%s' "$PROJECTS" )
  else
    ( PROJECTS=$1; eval "$lines"; printf '%s' "$PROJECTS" )
  fi
}
@test "PROJECTS unset: every project rke2-installer and seaweedfs-installer push to, jkroepke included" {
  out=$(projects_with unset)
  for p in rancher e2e-test-images velero fluent prometheus prometheus-operator kube-state-metrics jkroepke \
           ingress-nginx grafana kiwigrid bats chrislusf prom; do
    [[ " $out " == *" $p "* ]] || { echo "missing: $p (got: $out)"; return 1; }
  done
  [[ " $out " != *" library "* ]]   # Harbor makes library itself
}
@test "PROJECTS=\"\" gets the same list (ap-tools' contract keeps the :- form)" {
  [[ "$(projects_with '')" == "$(projects_with unset)" ]]
}
@test "an explicit PROJECTS list is kept exactly" {
  [[ "$(projects_with 'dev staging')" == "dev staging" ]]
}
@test "the README's table lists the same projects as the default" {
  out=$(projects_with unset)
  table=$(sed -n '/^### Projects for the Chubtoad5 tools/,/^### /p' "$BATS_TEST_DIRNAME/../../README.md" \
          | grep -oE '^\| `[a-z0-9-]+` \|' | tr -d '|` ' | sort | tr '\n' ' ')
  [[ "$table" == "$(tr ' ' '\n' <<< "$out" | sort | tr '\n' ' ')" ]] || { echo "table: $table"; echo "default: $out"; return 1; }
}
