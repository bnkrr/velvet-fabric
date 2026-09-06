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
local_ctl="${repo_root}/.local/bin/velvetctl"
babel_repo=${VELVET_BABEL_REPO:?set VELVET_BABEL_REPO to a local babel-rs checkout}
babel_revision=7e2371ce022919a0184da032b2f77e065877634c # v0.3.0
babel_target="${repo_root}/.local/cache/babel-rs-v0.3.0"
babel_binary="${babel_target}/release/babel-rs"

mkdir -p "$(dirname "${local_binary}")"
GOCACHE="${repo_root}/.local/cache/go-build" \
GOMODCACHE="${repo_root}/.local/cache/go-mod" \
CGO_ENABLED=0 GOOS=linux \
  "${go_bin}" build -trimpath -o "${local_binary}" ./cmd/velvetd
GOCACHE="${repo_root}/.local/cache/go-build" \
GOMODCACHE="${repo_root}/.local/cache/go-mod" \
CGO_ENABLED=0 GOOS=linux \
  "${go_bin}" build -trimpath -o "${local_ctl}" ./cmd/velvetctl

# Export the pinned commit without checking out or building sibling worktree edits.
mkdir -p "${repo_root}/.local/experiments"
babel_source=$(mktemp -d "${repo_root}/.local/experiments/babel-e2e.XXXXXXXX")
trap 'rm -rf -- "${babel_source}"' EXIT
git -C "${babel_repo}" archive "${babel_revision}" | tar -x -C "${babel_source}"
CARGO_TARGET_DIR="${babel_target}" \
  "${VELVET_CARGO_BIN:-cargo}" build --locked --release --manifest-path "${babel_source}/Cargo.toml" --package babel-rs
"${babel_binary}" --version

ssh "${ssh_config_args[@]}" -o ControlMaster=no -o ControlPath=none "${ssh_alias}" \
  "mkdir -p '${remote_root}'"
scp "${ssh_config_args[@]}" -o ControlMaster=no -o ControlPath=none \
  "${local_binary}" \
  "${local_ctl}" \
  "${repo_root}/tests/e2e/core-topology.sh" \
  "${repo_root}/tests/e2e/netns-static.sh" \
  "${repo_root}/tests/e2e/netns-core-crud.sh" \
  "${repo_root}/tests/e2e/netns-wg-admin-core.sh" \
  "${repo_root}/tests/e2e/generate-wg-admin-core.py" \
  "${repo_root}/tests/e2e/netns-dynamic.sh" \
  "${repo_root}/tests/e2e/generate-dynamic-core.py" \
  "${babel_binary}" \
  "${ssh_alias}:${remote_root}/"
case ${1:-all} in
  static)
    remote_tests="'${remote_root}/netns-static.sh' '${remote_root}/velvetd'"
    ;;
  crud)
    remote_tests="'${remote_root}/netns-core-crud.sh' '${remote_root}/velvetd'"
    ;;
  static-core)
    remote_tests="'${remote_root}/netns-wg-admin-core.sh' '${remote_root}/velvetd'"
    ;;
  dynamic)
    remote_tests="'${remote_root}/netns-dynamic.sh' '${remote_root}/velvetd' '${remote_root}/babel-rs' '${remote_root}/velvetctl'"
    ;;
  all)
    remote_tests="'${remote_root}/netns-static.sh' '${remote_root}/velvetd' && '${remote_root}/netns-core-crud.sh' '${remote_root}/velvetd' && '${remote_root}/netns-wg-admin-core.sh' '${remote_root}/velvetd' && '${remote_root}/netns-dynamic.sh' '${remote_root}/velvetd' '${remote_root}/babel-rs' '${remote_root}/velvetctl'"
    ;;
  *) echo "usage: $0 [all|static|crud|static-core|dynamic]" >&2; exit 2 ;;
esac
ssh "${ssh_config_args[@]}" -o ControlMaster=no -o ControlPath=none "${ssh_alias}" \
  "chmod 0700 '${remote_root}/velvetd' '${remote_root}/velvetctl' '${remote_root}/babel-rs' '${remote_root}/netns-static.sh' '${remote_root}/netns-core-crud.sh' '${remote_root}/netns-wg-admin-core.sh' '${remote_root}/generate-wg-admin-core.py' '${remote_root}/netns-dynamic.sh' '${remote_root}/generate-dynamic-core.py' && ${remote_tests}"
