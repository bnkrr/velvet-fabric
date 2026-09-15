#!/usr/bin/env bash
set -euo pipefail
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "${repo_root}"
selection=${1:-all}
case ${selection} in
  --help|-h)
    echo "usage: $0 [all|static|crud|static-core|dynamic|nat [CASE...]]"
    echo 'VM/build configuration: tests/VM.md'
    exit 0 ;;
  all|static|crud|static-core|dynamic) ;;
  nat)
    for nat_case in "${@:2}"; do
      case ${nat_case} in
        preserve|remap|delayed-remap|blocked|control-loss|random|observer-fallback|lifecycle|v6-lifecycle) ;;
        *)
          if [[ ! ${nat_case} =~ ^v[46]-(delayed-handshake|retry-blackout|policy-wakeup|policy-restart-query)$ &&
                ! ${nat_case} =~ ^v[46]-single-(preserve|remap|random)-(public|nat)-init$ &&
                ! ${nat_case} =~ ^v6-(native|filtered)-(a|b)-init$ &&
                ! ${nat_case} =~ ^v6-dual-(preserve|remap|blocked|random)$ ]]; then
            echo "unknown NAT scenario: ${nat_case}" >&2; exit 2
          fi ;;
      esac
    done ;;
  *) echo "unknown suite: ${selection}" >&2; exit 2 ;;
esac
source tests/lib/vm.sh
trap '[[ -z ${build_dir:-} ]] || rm -rf -- "${build_dir}"' EXIT
vm_configure
babel_revision=dbeede34abd8dff2422c39ab18a15949b0f38f11 # v0.6.0
vm_build with-ctl
tar -cf "${build_dir}/tests.tar" tests/e2e/*.sh tests/e2e/*.py
vm_upload velvetd velvetctl babel-rs tests.tar
command=$(python3 - "${asset_root}" "${selection}" "${@:2}" <<'PY'
import shlex, sys
root, selection, *cases = sys.argv[1:]
velvet, babel, ctl = (root + '/' + name for name in ('velvetd', 'babel-rs', 'velvetctl'))
commands = {
    'static': ['sh', root + '/tests/e2e/netns-static.sh', velvet],
    'crud': ['sh', root + '/tests/e2e/netns-core-crud.sh', velvet],
    'static-core': ['sh', root + '/tests/e2e/netns-wg-admin-core.sh', velvet],
    'dynamic': ['sh', root + '/tests/e2e/netns-dynamic.sh', velvet, babel, ctl],
    'nat': ['python3', root + '/tests/e2e/netns-udp-nat.py', velvet, babel, *cases],
}
selected = list(commands) if selection == 'all' else [selection]
print(' && '.join(shlex.join(commands[name]) for name in selected))
PY
)
vm_exec sh -c "${command}"
