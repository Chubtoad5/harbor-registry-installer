#!/usr/bin/env bats
# H17 (a database dump before a version change) and H18 (removing other versions' images after one).
load ../helpers
setup() {
  load_script install_harbor.sh
  setup_stubs
  data_dir=$(mktemp -d); db_dump_dir="$data_dir/backup/harbor-installer"
  mkdir -p "$data_dir/database"; echo data > "$data_dir/database/pg"
  base_dir=$(mktemp -d); mkdir -p "$base_dir/harbor-install-files"
  data_preexisting=1; previous_version=2.14.1; HARBOR_VERSION=2.15.0
  # A docker that has a running harbor-db, dumps a cluster, and lists images and containers from files
  IMAGES="$STUB_DIR/images"; PS="$STUB_DIR/ps"; : > "$IMAGES"; : > "$PS"
  stub docker '
case "$1 $2" in
  "inspect -f") echo true ;;
  "exec harbor-db") if [ "$3" = pg_dumpall ]; then [ -n "$DUMP_FAILS" ] && exit 1; printf -- "--\n-- PostgreSQL database cluster dump\n--\nSELECT 1;\n"; fi ;;
  "images --format") cat "'"$IMAGES"'" ;;
  "ps -a") cat "'"$PS"'" ;;
  "info -f") echo /var/lib/docker ;;
  "rmi "*) [ -n "$RMI_FAILS" ] && exit 1; exit 0 ;;
esac'
}
@test "H17: a version change leaves a private, valid dump named for the old version" {
  run dump_database_before_upgrade
  [ "$status" -eq 0 ]
  dump=$(ls "$db_dump_dir"/harbor-db-v2.14.1-*.sql.gz)
  [ "$(stat -c %a "$db_dump_dir")" = 700 ]
  [ "$(stat -c %a "$dump")" = 600 ]
  gzip -t "$dump"
  called 'exec harbor-db pg_dumpall -U postgres --clean --if-exists'
  [[ "$output" == *"Restoring the database after a failed upgrade"* ]]
}
@test "H17: the same version, or a first install, makes no dump" {
  previous_version=2.15.0
  dump_database_before_upgrade
  [ ! -e "$db_dump_dir" ]
  previous_version=2.14.1; data_preexisting=0
  dump_database_before_upgrade
  [ ! -e "$db_dump_dir" ]
  ! called pg_dumpall || false
}
@test "H17: an unknown earlier version still dumps" {
  previous_version=""
  dump_database_before_upgrade >/dev/null
  ls "$db_dump_dir"/harbor-db-vunknown-*.sql.gz
}
@test "H17: a failed dump stops the run and leaves no file" {
  export DUMP_FAILS=1
  run dump_database_before_upgrade
  [ "$status" -eq 1 ]
  [[ "$output" == *"Nothing has been changed"* ]]
  [ -z "$(ls -A "$db_dump_dir")" ]
}
@test "H17: a dump that isn't a cluster dump stops the run" {
  stub docker 'case "$1 $2" in "inspect -f") echo true ;; "exec harbor-db") [ "$3" = pg_dumpall ] && echo "not a dump" ;; esac'
  run dump_database_before_upgrade
  [ "$status" -eq 1 ]
  [[ "$output" == *"empty or incomplete"* ]]
}
@test "H17: HARBOR_DB_DUMP=false skips it, with a warning" {
  HARBOR_DB_DUMP=false
  run dump_database_before_upgrade
  [ "$status" -eq 0 ]
  [[ "$output" == *"WARNING: HARBOR_DB_DUMP=false"* ]]
  ! called pg_dumpall || false
}
@test "H17: harbor-db stopped: the installed version's database starts alone for the dump" {
  mkdir -p /opt/harbor; touch /opt/harbor/docker-compose.yml
  stub docker '
case "$1 $2" in
  "inspect -f") echo false ;;
  "exec harbor-db") [ "$3" = pg_dumpall ] && printf -- "-- PostgreSQL database cluster dump\n" ;;
esac'
  run dump_database_before_upgrade
  rm -f /opt/harbor/docker-compose.yml
  [ "$status" -eq 0 ]
  called 'compose -f /opt/harbor/docker-compose.yml up -d postgresql'
}
@test "H17: uninstall removes the dumps, and keeps another tool's backups" {
  mkdir -p "$db_dump_dir" "$data_dir/backup/other"; touch "$db_dump_dir/x.sql.gz" "$data_dir/backup/other/keep"
  PURGE_DATA=false
  remove_harbor_data >/dev/null
  [ ! -e "$db_dump_dir" ]
  [ -e "$data_dir/backup/other/keep" ]
}
@test "H18: other versions' unused images go; the running version's and in-use ones stay" {
  printf '%s\n' goharbor/harbor-core:v2.15.0 goharbor/harbor-core:v2.14.1 goharbor/harbor-db:v2.14.1 \
    goharbor/harbor-db:v2.13.2 'goharbor/prepare:<none>' goharbor/harbor-log:v2.14.1 > "$IMAGES"
  printf '%s\n' goharbor/harbor-core:v2.15.0 goharbor/harbor-log:v2.14.1 > "$PS"
  run old_harbor_images
  [ "$output" = $'goharbor/harbor-core:v2.14.1\ngoharbor/harbor-db:v2.14.1\ngoharbor/harbor-db:v2.13.2' ]
}
@test "H18: removal runs after a version change only, and HARBOR_REMOVE_OLD_IMAGES=false keeps them" {
  printf '%s\n' goharbor/harbor-core:v2.15.0 goharbor/harbor-core:v2.14.1 > "$IMAGES"
  touch "$base_dir/harbor-install-files/harbor-offline-installer-v2.14.1.tgz"
  run remove_old_images
  [[ "$output" == *"Removed 1 goharbor image(s)"* ]]
  [[ "$output" == *"Kept "*"harbor-offline-installer-v2.14.1.tgz"* ]]
  called 'rmi goharbor/harbor-core:v2.14.1'
  ! called 'rmi goharbor/harbor-core:v2.15.0' || false
  : > "$STUB_LOG"
  HARBOR_REMOVE_OLD_IMAGES=false remove_old_images >/dev/null
  ! called rmi || false
  previous_version=2.15.0
  remove_old_images
  ! called rmi || false
}
@test "H18: an image that won't go is a warning, not a failure" {
  printf '%s\n' goharbor/harbor-core:v2.14.1 > "$IMAGES"
  export RMI_FAILS=1
  run remove_old_images
  [ "$status" -eq 0 ]
  [[ "$output" == *"WARNING: couldn't remove goharbor/harbor-core:v2.14.1"* ]]
}
