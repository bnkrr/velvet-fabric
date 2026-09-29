# Local binary helper

在 Linux 本地一次构建 `velvetd`、`velvetctl` 和 `babel-rs`：

```sh
# 在 velvet/ 父目录运行，也可以在 velvet-fabric 内运行 scripts/build-local.py。
python3 velvet-fabric/scripts/build-local.py
```

默认读取 Fabric 和相邻 `babel-rs/` 的**当前工作区**，包含未提交改动。
不会执行 git pull、fetch、checkout 或修改索引。需要 Python 3.10+、Git、Go 和 Rust
工具链，以及 Cargo 依赖所需的本机链接器；首次构建可能下载 Go/Cargo 依赖。
Go 版本跟随 go.mod，Rust 版本须满足 Babel 的 Cargo.toml。

结果位于 `velvet-fabric/.local/dist/latest/`：

```text
velvetd
velvetctl
babel-rs
BUILDINFO.json
SHA256SUMS
```

`latest` 是指向一次完整构建的相对软链接。构建、可执行文件冒烟检查和 Babel 示例
配置检查全部成功后才更新它；失败时保留上一次可用结果，每次成功的历史目录也保留。
这是本机构建，不是正式发布，也不自动安装、重启服务或配置网络。

```sh
velvet-fabric/.local/dist/latest/velvetd --version
velvet-fabric/.local/dist/latest/babel-rs --version
(cd velvet-fabric/.local/dist/latest && sha256sum -c SHA256SUMS)
```

需要安装到本机系统目录时，由用户执行：

```sh
sudo install -m 0755 velvet-fabric/.local/dist/latest/{velvetd,velvetctl,babel-rs} /usr/local/bin/
```

NodeSpec 的 `babel.executable` 设置成实际安装路径，例如 `/usr/local/bin/babel-rs`。
也可以将二进制复制到目标 Linux 节点。当前 helper 仅构建本机架构 amd64/arm64；
Babel 使用本机 Rust target/系统 ABI，不承诺跨发行版静态可移植性。

## 构建已验证的 Babel 配套版本

Fabric E2E 使用明确的 Babel 提交，并不自动跟随 Babel 的 HEAD。
默认工作区如果与该提交不同，helper 会提示，并在 BUILDINFO.json 中记录这种区别。
若希望 Fabric 使用当前改动，而 Babel 使用已验证提交：

```sh
python3 velvet-fabric/scripts/build-local.py --babel-source pinned
```

提交号直接读取 Fabric 的 `tests/babel-revision`，与 CI 和 VM 测试入口共用。通过 `git archive` 从本地
Babel 仓库导出到临时目录，不修改 Babel 的工作区、暂存区或分支。该提交须已存在
于本地仓库；缺失时会报错，不会擅自联网更新仓库。Fabric 特权 E2E 仍须使用此版本。

## 其他选项

```sh
python3 velvet-fabric/scripts/build-local.py \
  --babel-repo /path/to/babel-rs \
  --go /path/to/go \
  --cargo /path/to/cargo \
  --output /path/to/builds
```

默认从 PATH 查找工具，也支持用户目录下的 `.local/go/bin/go`、`.cargo/bin/cargo`。
可用 `VELVET_GO_BIN` / `VELVET_CARGO_BIN` 指定工具；`GOCACHE`、`GOMODCACHE`、
`CARGO_TARGET_DIR` 也可指定缓存目录。默认缓存位于 Fabric 的 `.local/cache/`。
构建时请不要同时编辑待编译的源码。BUILDINFO 记录提交和工作区是否有改动，
不会把未提交补丁打包成可重现的源码归档。

脚本回归测试：`python3 -m unittest discover -s velvet-fabric/tests/build -v`。
