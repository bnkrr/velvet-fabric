# Running tests on a VM

The E2E, directed and endless suites share a local-build/remote-run helper.
Choose a disposable Linux test host with root SSH access, kernel WireGuard,
Python 3.11+, iproute2, nftables, ping, sysctl and ss. Capture additionally
needs tcpdump. The build machine needs Bash, Python 3, Git, tar, SSH, Go and
Cargo. The commit in `tests/babel-revision` must exist in the local Babel checkout
for default builds. `all` includes systemd resilience and requires systemd as PID 1;
use the explicitly narrower `netns` selection on hosts without systemd.

Set these variables before invoking a wrapper:

```sh
export VELVET_VM_HOST=root@vm.example
export VELVET_VM_REMOTE_ROOT=/srv/velvet-tests
export VELVET_BABEL_REPO=/path/to/babel-rs
tests/e2e/run-on-vm.sh all
tests/directed/run-on-vm.sh --case data-mtu --family both
tests/endless/run-on-vm.sh --nodes 8 --rounds 6
```

Replace the example host and paths with your own. All three variables are
required; the helpers never select a personal host or project directory.
You can put machine-specific defaults in the ignored `.local/vm.env` shell
file, which all three wrappers source before building. Use shell defaults
such as `: "${VELVET_VM_HOST:=root@vm.example}"` there to let caller environment
values take precedence. Keep credentials in your SSH configuration or agent.
Help and the endless `--plan` mode need neither VM configuration nor a build.

| Setting | Behavior |
| --- | --- |
| `VELVET_VM_HOST` | SSH destination: host alias or `user@host` |
| `VELVET_VM_REMOTE_ROOT` | Absolute directory for new, unique per-run assets |
| `VELVET_BABEL_REPO` | Local Babel checkout |
| `VELVET_BABEL_SOURCE` | `revision` (default) builds a clean Git archive; `working-tree` explicitly includes uncommitted changes |
| `VELVET_BABEL_REVISION` | Optional full 40-character SHA override; default `tests/babel-revision`; incompatible with `working-tree` |
| `VELVET_GO_BIN`, `VELVET_CARGO_BIN` | Optional executable paths; default to `go` and `cargo` on PATH |
| `VELVET_SSH_CONFIG` | Optional `ssh -F` file; otherwise SSH uses its normal configuration |

Go builds target Linux and honor `GOARCH`, `GOCACHE` and `GOMODCACHE`. Cargo
honors the caller's `CARGO_HOME`, `RUSTUP_TOOLCHAIN`, `CARGO_BUILD_TARGET` and
configuration. `CARGO_TARGET_DIR` is also honored; its default is the repository's
ignored `.local/cache/babel-rs`. The actual executable path comes from Cargo's
artifact report, including when a custom target or cache directory is used.
The helpers do not install toolchains or cross-linkers. By default, use a Linux
build machine and VM with matching architectures; for cross-compilation,
configure both toolchains for the VM (for example `GOARCH=arm64` and
`CARGO_BUILD_TARGET=aarch64-unknown-linux-gnu`) and supply the required linker.

Only binaries and test runtime files are sent through SSH/tar. Every invocation
uses a new asset directory, including E2E, so it cannot replace another run's
active binaries. Spaces and shell punctuation in configured paths are quoted.
Run finite suites serially on small hosts. Endless is opt-in; unattended runs
need a persistent VM session. The ordinary netns suites do not install services or timers.

The `resilience` and `resilience-dynamic` selections install temporary systemd
units using the shipped hardening, isolated namespaces and shorter test deadlines.
Both are included in `all`; `resilience-all` runs just those two. `ProtectHome` is
disabled only in the fixture so staged binaries under a build account's home can
run. Production units retain `ProtectHome=true`. SIGTERM/SIGINT trigger cleanup.

FIB recovery is always required by the resilience tests: legacy Babel builds fail
preflight before services or namespaces are created. The relay test blocks Babel
UDP/6696 during a crash, checks retained IPv4/IPv6 forwarding, then checks that
fresh routes take over. Dynamic tests verify persisted expiry and Link regrowth.

For uncommitted changes in both repositories:

```sh
VELVET_BABEL_SOURCE=working-tree tests/e2e/run-on-vm.sh resilience-all
```

The standard path needs no custom binary staging or extra FIB flag. CI uses the
shared exact revision and runs static/dynamic resilience in separate hosted Linux
VM jobs; lack of systemd or the required Babel capability fails the job.
