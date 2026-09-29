# Shared local build and SSH deployment for the opt-in VM test wrappers.
# Callers set repo_root and install a cleanup trap for build_dir.

vm_configure() {
  if [[ -f ${repo_root}/.local/vm.env ]]; then
    source "${repo_root}/.local/vm.env"
  fi
  : "${VELVET_VM_HOST:?set VELVET_VM_HOST to the test SSH destination}"
  : "${VELVET_VM_REMOTE_ROOT:?set VELVET_VM_REMOTE_ROOT to an absolute test asset directory}"
  : "${VELVET_BABEL_REPO:?set VELVET_BABEL_REPO to a local babel-rs Git checkout}"
  [[ ${VELVET_VM_HOST} != -* && ${VELVET_VM_REMOTE_ROOT} == /* && ${VELVET_VM_REMOTE_ROOT} != / ]] || {
    echo 'invalid VM host or absolute remote asset directory' >&2; return 2;
  }
  babel_source=${VELVET_BABEL_SOURCE:-revision}
  babel_revision=${VELVET_BABEL_REVISION:-$(cat "${repo_root}/tests/babel-revision")}
  case "$babel_source" in
    revision)
      [[ $babel_revision =~ ^[0-9a-f]{40}$ ]] || {
        echo 'VELVET_BABEL_REVISION must be a full 40-character commit SHA' >&2; return 2;
      } ;;
    working-tree)
      [[ -z ${VELVET_BABEL_REVISION:-} ]] || {
        echo 'working-tree cannot be combined with VELVET_BABEL_REVISION' >&2; return 2;
      } ;;
    *) echo 'VELVET_BABEL_SOURCE must be revision or working-tree' >&2; return 2 ;;
  esac
  go_bin=${VELVET_GO_BIN:-go}
  cargo_bin=${VELVET_CARGO_BIN:-cargo}
  babel_repo=$(cd "${VELVET_BABEL_REPO}" && pwd)
  ssh_args=(-o ControlMaster=no -o ControlPath=none)
  if [[ -n ${VELVET_SSH_CONFIG:-} ]]; then
    ssh_args+=(-F "${VELVET_SSH_CONFIG}")
  fi
  mkdir -p "${repo_root}/.local/experiments"
  build_dir=$(mktemp -d "${repo_root}/.local/experiments/vm-build.XXXXXXXX")
  asset_root="${VELVET_VM_REMOTE_ROOT%/}/assets-$(date -u +%Y%m%dT%H%M%S)-$(basename "${build_dir}")"
}

vm_build() {
  CGO_ENABLED=0 GOOS=linux "${go_bin}" build -trimpath -o "${build_dir}/velvetd" ./cmd/velvetd
  if [[ ${1:-} == with-ctl ]]; then
    CGO_ENABLED=0 GOOS=linux "${go_bin}" build -trimpath -o "${build_dir}/velvetctl" ./cmd/velvetctl
  fi
  if [[ $babel_source == working-tree ]]; then
    babel_manifest="${babel_repo}/Cargo.toml"
    printf 'Babel source: working tree %s\n' "${babel_repo}"
  else
    mkdir "${build_dir}/babel-source"
    git -C "${babel_repo}" archive "${babel_revision}" | tar -x -C "${build_dir}/babel-source"
    babel_manifest="${build_dir}/babel-source/Cargo.toml"
    printf 'Babel source: revision %s\n' "${babel_revision}"
  fi
  # Respect Cargo's environment/config, including target, toolchain and caches.
  # Its artifact output also handles cross targets and custom target directories.
  CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${repo_root}/.local/cache/babel-rs}" \
    "${cargo_bin}" build --locked --release --message-format=json \
    --manifest-path "${babel_manifest}" --package babel-rs > "${build_dir}/cargo.jsonl"
  python3 - "${build_dir}" <<'PY'
import json, pathlib, shutil, sys
root = pathlib.Path(sys.argv[1])
artifacts = [json.loads(line) for line in (root / 'cargo.jsonl').read_text().splitlines()]
paths = {item['executable'] for item in artifacts if item.get('reason') == 'compiler-artifact'
         and item.get('target', {}).get('name') == 'babel-rs' and item.get('executable')}
if len(paths) != 1:
    raise SystemExit('Cargo did not report one babel-rs executable')
shutil.copy2(paths.pop(), root / 'babel-rs')
PY
}

vm_command() {
  python3 -c 'import shlex,sys; print(shlex.join(sys.argv[1:]))' "$@"
}

vm_upload() {
  printf 'VM assets: %s\n' "${asset_root}"
  ssh "${ssh_args[@]}" "${VELVET_VM_HOST}" "$(vm_command mkdir -p "${asset_root}")"
  tar -cf - -C "${build_dir}" "$@" | ssh "${ssh_args[@]}" "${VELVET_VM_HOST}" \
    "$(vm_command tar -xf - -C "${asset_root}")"
  ssh "${ssh_args[@]}" "${VELVET_VM_HOST}" \
    "$(vm_command sh -c 'cd "$1" && tar -xf tests.tar' sh "${asset_root}")"
}

vm_exec() {
  ssh -tt "${ssh_args[@]}" "${VELVET_VM_HOST}" "$(vm_command "$@")"
}
