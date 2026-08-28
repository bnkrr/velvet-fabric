#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
go_bin=${VELVET_GO_BIN:-/home/bnkr/.local/go/bin/go}
ssh_config=${VELVET_SSH_CONFIG:-/home/bnkr/.ssh/config}
ssh_alias=${VELVET_VM_SSH_ALIAS:-vm-debsrv}
remote_root=${VELVET_VM_REMOTE_ROOT:-/root/proj/velvet/velvet-fabric/.local/e2e}
local_binary="${repo_root}/.local/bin/velvetd-linux-amd64"

mkdir -p "$(dirname "${local_binary}")"
GOCACHE="${repo_root}/.local/cache/go-build" \
GOMODCACHE="${repo_root}/.local/cache/go-mod" \
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  "${go_bin}" build -trimpath -o "${local_binary}" ./cmd/velvetd

ssh -F "${ssh_config}" -o ControlMaster=no -o ControlPath=none "${ssh_alias}" \
  "mkdir -p '${remote_root}'"
scp -F "${ssh_config}" -o ControlMaster=no -o ControlPath=none \
  "${local_binary}" \
  "${repo_root}/tests/e2e/netns-static.sh" \
  "${repo_root}/tests/e2e/netns-core-crud.sh" \
  "${repo_root}/tests/e2e/netns-wg-admin-core.sh" \
  "${repo_root}/tests/e2e/generate-wg-admin-core.py" \
  "${ssh_alias}:${remote_root}/"
ssh -F "${ssh_config}" -o ControlMaster=no -o ControlPath=none "${ssh_alias}" \
  "chmod 0700 '${remote_root}/velvetd-linux-amd64' '${remote_root}/netns-static.sh' '${remote_root}/netns-core-crud.sh' '${remote_root}/netns-wg-admin-core.sh' '${remote_root}/generate-wg-admin-core.py' && '${remote_root}/netns-static.sh' '${remote_root}/velvetd-linux-amd64' && '${remote_root}/netns-core-crud.sh' '${remote_root}/velvetd-linux-amd64' && '${remote_root}/netns-wg-admin-core.sh' '${remote_root}/velvetd-linux-amd64'"
