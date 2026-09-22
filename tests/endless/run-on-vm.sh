#!/usr/bin/env bash
set -euo pipefail
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "${repo_root}"
detach=false
forwarded=()
for argument in "$@"; do
  if [[ ${argument} == --detach ]]; then detach=true; else forwarded+=("${argument}"); fi
done
set -- "${forwarded[@]}"
for argument in "$@"; do
  case "$argument" in
    --help|-h|--plan)
      if [[ ${argument} != --plan ]]; then
        printf '%s\n' 'VM wrapper option: --detach runs in a persistent VM session with rotating progress logs.'
      fi
      exec env PYTHONDONTWRITEBYTECODE=1 python3 tests/endless/netns.py "$@"
      ;;
  esac
done
PYTHONDONTWRITEBYTECODE=1 python3 tests/endless/netns.py --validate "$@"
source tests/lib/vm.sh
trap '[[ -z ${build_dir:-} ]] || rm -rf -- "${build_dir}"' EXIT
vm_configure
babel_revision=dbeede34abd8dff2422c39ab18a15949b0f38f11 # v0.6.0
vm_build
tar -cf "${build_dir}/tests.tar" tests/endless/*.py
vm_upload velvetd babel-rs tests.tar
if ${detach}; then
  # Each run has immutable assets and its own log/exit record. No service,
  # timer or automatic restart: the first failure remains visible.
  ssh "${ssh_args[@]}" "${VELVET_VM_HOST}" "$(vm_command sh -c '
    root=$1; shift
    nohup setsid sh -c '\''root=$1; shift; "$@"; code=$?; printf "%s\n" "$code" > "$root/exit-code"; exit "$code"'\'' \
      sh "$root" "$@" > "$root/console.log" 2>&1 < /dev/null &
    printf "%s\n" "$!" > "$root/launcher.pid"
  ' sh "${asset_root}" env PYTHONDONTWRITEBYTECODE=1 python3 "${asset_root}/tests/endless/netns.py" \
      "${asset_root}/velvetd" "${asset_root}/babel-rs" --artifacts "${asset_root}/run" --quiet "$@")"
  printf 'Detached VM run: %s\n' "${asset_root}"
  exit 0
fi
# Run unattended tests in a persistent session on the VM; PTY hangup otherwise
# reaches the runner's signal cleanup. Failed assets are retained for replay.
vm_exec env PYTHONDONTWRITEBYTECODE=1 python3 "${asset_root}/tests/endless/netns.py" \
  "${asset_root}/velvetd" "${asset_root}/babel-rs" --artifacts "${asset_root}/run" "$@"
