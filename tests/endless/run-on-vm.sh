#!/usr/bin/env bash
set -euo pipefail
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "${repo_root}"
for argument in "$@"; do
  case "$argument" in
    --help|-h|--plan)
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
# Run unattended tests in a persistent session on the VM; PTY hangup otherwise
# reaches the runner's signal cleanup. Failed assets are retained for replay.
vm_exec env PYTHONDONTWRITEBYTECODE=1 python3 "${asset_root}/tests/endless/netns.py" \
  "${asset_root}/velvetd" "${asset_root}/babel-rs" --artifacts "${asset_root}/run" "$@"
