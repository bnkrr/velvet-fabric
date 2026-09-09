#!/usr/bin/env bash
set -euo pipefail
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "${repo_root}"
for argument in "$@"; do
  case "$argument" in
    --help|-h|--plan)
      exec env PYTHONDONTWRITEBYTECODE=1 python3 "${repo_root}/tests/endless/netns.py" "$@"
      ;;
  esac
done
PYTHONDONTWRITEBYTECODE=1 python3 "${repo_root}/tests/endless/netns.py" --validate "$@"
ssh_config_args=()
if [[ -n ${VELVET_SSH_CONFIG:-} ]]; then
  ssh_config_args=(-F "${VELVET_SSH_CONFIG}")
fi
ssh_alias=${VELVET_VM_HOST:?set VELVET_VM_HOST to the test SSH destination}
remote_root=${VELVET_VM_REMOTE_ROOT:?set VELVET_VM_REMOTE_ROOT to an absolute test asset directory}
ssh_args=("${ssh_config_args[@]}" -o ControlMaster=no -o ControlPath=none)
mkdir -p "${repo_root}/.local/experiments"
build_dir=$(mktemp -d "${repo_root}/.local/experiments/endless-build.XXXXXXXX")
trap 'rm -rf -- "${build_dir}"' EXIT
GOCACHE="${repo_root}/.local/cache/go-build" GOMODCACHE="${repo_root}/.local/cache/go-mod" \
CGO_ENABLED=0 GOOS=linux \
  "${VELVET_GO_BIN:-go}" build -trimpath -o "${build_dir}/velvetd" ./cmd/velvetd
# Build the integration pin, never the sibling's possibly modified worktree.
babel_revision=b5e15d857d776c60179dcb6078a524b56b3ced94 # v0.4.1
babel_repo=${VELVET_BABEL_REPO:?set VELVET_BABEL_REPO to a local babel-rs checkout}
babel_target="${repo_root}/.local/cache/babel-rs-v0.4.1"
mkdir "${build_dir}/babel-source"
git -C "${babel_repo}" archive "${babel_revision}" | tar -x -C "${build_dir}/babel-source"
CARGO_TARGET_DIR="${babel_target}" \
  "${VELVET_CARGO_BIN:-cargo}" build --locked --release --manifest-path "${build_dir}/babel-source/Cargo.toml" --package babel-rs
# Unique assets per invocation: never overwrite an executable used by another run.
asset_root="${remote_root}/assets-$(date -u +%Y%m%dT%H%M%S)-$(basename "${build_dir}")"
mkdir_command=$(python3 -c 'import shlex,sys; print(shlex.join(["mkdir", "-p", sys.argv[1]]))' "${asset_root}")
ssh "${ssh_args[@]}" "${ssh_alias}" "${mkdir_command}"
# Quote the remote path for scp's remote-shell mode too.
scp_root=$(python3 -c 'import shlex,sys; print(shlex.quote(sys.argv[1] + "/"))' "${asset_root}")
scp "${ssh_args[@]}" "${build_dir}/velvetd" "${babel_target}/release/babel-rs" \
  "${repo_root}/tests/endless/netns.py" "${repo_root}/tests/endless/model.py" "${repo_root}/tests/endless/nat.py" "${ssh_alias}:${scp_root}"
remote_command=$(python3 - "${asset_root}" "$@" <<'PY'
import shlex
import sys
root = sys.argv[1]
print("cd " + shlex.quote(root) + " && exec " + shlex.join([
    "env", "PYTHONDONTWRITEBYTECODE=1", "python3", root + "/netns.py", root + "/velvetd", root + "/babel-rs",
    "--artifacts", root + "/run", *sys.argv[2:]]))
PY
)
# PTY hangup/interrupt reaches the runner's signal cleanup. Run unattended tests
# in a persistent session on the VM. Keep assets and failure records for replay.
ssh -tt "${ssh_args[@]}" "${ssh_alias}" "${remote_command}"
