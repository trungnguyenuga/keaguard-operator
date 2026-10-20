#!/usr/bin/env bash
set -euo pipefail

fail() {
  printf 'M2 Docker build environment: %s\n' "$1" >&2
  exit 1
}

[[ $# -ge 5 && $4 == -- ]] || fail 'expected task, acceptance, build directories and a command'
task_dir=$1
accept_dir=$2
build_dir=$3
shift 4

[[ $accept_dir == "$task_dir/docker-config" && $build_dir == "$task_dir/docker-build-config" && $accept_dir != "$build_dir" ]] || fail 'build and acceptance Docker configs must differ and use fixed sibling paths'
[[ ${DOCKER_CONFIG-} == "$accept_dir" ]] || fail 'DOCKER_CONFIG must select the acceptance directory before the isolated build'
[[ -z ${DOCKER_AUTH_CONFIG-} ]] || fail 'DOCKER_AUTH_CONFIG is not allowed'
[[ -z ${BUILDKIT_HOST-} && -z ${BUILDX_BUILDER-} ]] || fail 'external BuildKit builder selection is not allowed'

check_private_dir() {
  local path=$1 label=$2
  [[ ! -L $path && -d $path ]] || fail "$label must be a non-symlink directory"
  [[ $(stat -c %u -- "$path") == "$(id -u)" ]] || fail "$label has foreign ownership"
  [[ $(stat -c %a -- "$path") == 700 ]] || fail "$label must have mode 0700"
}

check_private_dir "$task_dir" 'task directory'
check_private_dir "$accept_dir" 'acceptance Docker config'
[[ -z $(find "$accept_dir" -mindepth 1 -print -quit) ]] || fail 'acceptance Docker config must remain empty'

if [[ -e $build_dir || -L $build_dir ]]; then
  check_private_dir "$build_dir" 'build Docker config'
else
  (umask 077; mkdir -m 0700 -- "$build_dir")
  check_private_dir "$build_dir" 'build Docker config'
fi
[[ ! -e $build_dir/config.json && ! -L $build_dir/config.json ]] || fail 'credential config is not allowed in build Docker config'
[[ -z $(find "$build_dir" -mindepth 1 -type l -print -quit) ]] || fail 'build Docker config contains a symlink'
[[ -z $(find "$build_dir" -mindepth 1 ! -user "$(id -u)" -print -quit) ]] || fail 'build Docker config contains foreign ownership'

exec env DOCKER_CONFIG="$build_dir" "$@"
