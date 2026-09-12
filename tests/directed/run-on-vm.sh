#!/usr/bin/env bash
set -euo pipefail
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "${repo_root}"
if [[ ${1:-} == --help || ${1:-} == -h ]]; then
  exec python3 tests/directed/suite.py --help
fi
source tests/lib/vm.sh
trap '[[ -z ${build_dir:-} ]] || rm -rf -- "${build_dir}"' EXIT
vm_configure
babel_revision=dbeede34abd8dff2422c39ab18a15949b0f38f11 # v0.6.0
vm_build
tar -cf "${build_dir}/tests.tar" tests/directed/*.py tests/endless/*.py
vm_upload velvetd babel-rs tests.tar
vm_exec env PYTHONDONTWRITEBYTECODE=1 python3 "${asset_root}/tests/directed/suite.py" \
  "${asset_root}/velvetd" "${asset_root}/babel-rs" --artifacts "${asset_root}/results" "$@"
