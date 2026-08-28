#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
go_bin=${VELVET_GO_BIN:-go}
ssh_config_args=()
if [[ -n ${VELVET_SSH_CONFIG:-} ]]; then
  ssh_config_args=(-F "${VELVET_SSH_CONFIG}")
fi
ssh_alias=${VELVET_VM_HOST:?set VELVET_VM_HOST to the test SSH destination}
remote_root=${VELVET_VM_REMOTE_ROOT:?set VELVET_VM_REMOTE_ROOT to an absolute test asset directory}
local_binary="${repo_root}/.local/bin/velvetd"

mkdir -p "$(dirname "${local_binary}")"
GOCACHE="${repo_root}/.local/cache/go-build" \
GOMODCACHE="${repo_root}/.local/cache/go-mod" \
CGO_ENABLED=0 GOOS=linux \
  "${go_bin}" build -trimpath -o "${local_binary}" ./cmd/velvetd

ssh "${ssh_config_args[@]}" -o ControlMaster=no -o ControlPath=none "${ssh_alias}" \
  "mkdir -p '${remote_root}'"
scp "${ssh_config_args[@]}" -o ControlMaster=no -o ControlPath=none \
  "${local_binary}" \
  "${repo_root}/tests/e2e/netns-static.sh" \
  "${repo_root}/tests/e2e/netns-core-crud.sh" \
  "${repo_root}/tests/e2e/netns-wg-admin-core.sh" \
  "${repo_root}/tests/e2e/generate-wg-admin-core.py" \
  "${ssh_alias}:${remote_root}/"
ssh "${ssh_config_args[@]}" -o ControlMaster=no -o ControlPath=none "${ssh_alias}" \
  "chmod 0700 '${remote_root}/velvetd' '${remote_root}/netns-static.sh' '${remote_root}/netns-core-crud.sh' '${remote_root}/netns-wg-admin-core.sh' '${remote_root}/generate-wg-admin-core.py' && '${remote_root}/netns-static.sh' '${remote_root}/velvetd' && '${remote_root}/netns-core-crud.sh' '${remote_root}/velvetd' && '${remote_root}/netns-wg-admin-core.sh' '${remote_root}/velvetd'"
