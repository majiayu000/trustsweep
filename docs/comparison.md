# 功能对比

2026-10-22 重新实查。star 数和推送时间来自 `gh api repos/<repo>`，通告数据来自 `api.osv.dev`。syft、grype、trivy、osv-scanner 本机没有安装，**没有实际运行**；表里对它们的判断依据是两点：它们按包版本比对通告的工作方式，以及 OSV 里现在有哪些通告。小工具则以各自 README 的说明为准。

## 现在有哪些通告（决定版本型扫描器能查到什么）

| 通告 | 发布 | 覆盖的包 | 修复版本 |
|---|---|---|---|
| GHSA-6q48-6c7w-9gw2 / PYSEC-2026-4320 | 10-20 | PyPI certifi | 2026.10.19 |
| RUSTSEC-2026-0381 | 10-19 | crates.io webpki-roots | 0.26.11、1.0.10 |
| RUSTSEC-2026-0383 | 10-19 | crates.io webpki-root-certs | 0.26.11、1.0.10 |
| RUSTSEC-2026-0382 | 10-20 | crates.io rustls-webpki | 0.103.16 |
| GO-2026-6809 | 10-21 | Go stdlib（crypto/x509） | 1.26.10、1.27.3 |

OSV 里**查不到**以下几类的相关通告：pip 25.0.1（它自带 certifi）、grpcio 1.78.0（自带 `roots.pem`）、Alpine 的 ca-certificates 20260909-r0、Debian 12 的 ca-certificates 20230311+deb12u1、Node.js、Bun、Deno、Electron、JDK。版本型扫描器对这些查不出问题，而 trustsweep 在 `examples/` 的实测中把它们都找了出来。

## 逐项对比

| 能力 | trustsweep | syft 9713★ | grype 13069★ / trivy 38600★ / osv-scanner | git-pkgs/certs 1★ | 0xAJStrike/emsign-trust-scan 3★ | wakumo/emudhra-check（新） |
|---|---|---|---|---|---|---|
| 形态 | Rust 单二进制 CLI | Go CLI（SBOM） | Go CLI（漏洞匹配） | Go 库加 CLI | Python 和 PowerShell 脚本 | macOS bash 脚本 |
| 直接结论"这份库仍信任被撤销的 CA" | ✅ | ❌ | 间接：只对上表通告覆盖的**已声明的包** | ❌ 只盘点，明确说"不代表有漏洞" | ✅ | ✅ |
| 按文件内容找证书，不依赖包版本 | ✅ | ❌（证书盘点 [#5191](https://github.com/anchore/syft/issues/5191) 仍 open，无 PR） | ❌ | ✅ | ✅，只看固定位置 | 部分：读已知 CA 文件 |
| 第三方包自带的副本（pip `_vendor/certifi`、grpcio `roots.pem`） | ✅ | ❌ | ❌（无通告） | ✅ 盘点 | pip ✅，其它只认已知路径 | pip ✅（实际连接测试） |
| 二进制里的 PEM 或 DER（node、bun、deno、Electron） | ✅ | ❌ | ❌（无通告） | ✅ 盘点 | ❌ | 只看版本号 |
| 只嵌入公钥字节的信任锚（编译进二进制的 webpki-roots，例如 uv、lancedb 原生 addon） | ✅ | ❌ | 仅当二进制带 cargo-auditable 元数据时，能按 RUSTSEC 匹配 | 未见 | ❌ | 只看 uv 的版本号 |
| 源码里的字节串字面量（webpki-root-certs、C 数组） | ✅ | ❌ | 按 Cargo.lock 匹配 RUSTSEC | ✅ | ❌ | ❌ |
| 嵌套压缩包（wheel、jar、tgz、crate、gem） | ✅ 在内存里展开 | 包级 | 包级 | ✅ | ❌ | ❌ |
| Java cacerts（JKS、PKCS#12） | ✅ | ❌ | ❌ | ✅ | ✅ | ✅（连接测试 + `blocked.certs`） |
| 容器镜像 | ✅ 逐层扫描，识别 whiteout，标出被覆盖的文件，支持 gzip 和 zstd 层 | 有镜像扫描，但不盘点证书 | 按包扫描 | tar 能读，但不按层处理（未见） | 读 overlay2 目录，需要 root | `docker create` 后读 CA 文件 |
| 给出属于哪个包、该升到什么版本 | ✅（dist-info、package.json、pom、JDK release、dpkg/apk/distroless、Homebrew、cargo） | — | ✅，限于有通告的包 | ❌ 需要调用方自己补坐标 | 部分 | ✅ |
| 同时对照 OneCRL 全量 | ✅ 1262 条 | ❌ | ❌ | ❌ | ❌ | ❌ |
| 数据源自动更新 | ✅ `feed update`，失败直接报错 | — | ✅ 漏洞库 | 内置快照 | 需要手动刷新 `tools/sources` | 内置 |
| 离线运行 | ✅ | ✅ | 漏洞库需要先下载 | ✅ | ✅ | ❌（要连 12 台测试服务器） |
| 实际连接测试 | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| 自动修复 | ❌，只报告 | ❌ | ❌ | ❌ | ❌ | ✅ `--fix` |
| 输出 | text、JSON、SARIF | JSON、SBOM | JSON、SARIF | JSON Lines | text、JSON、CSV | 文本日志 |
| CI 门禁（退出码） | ✅ 0/1/2 | — | ✅ | 0/1/2 | ✅ 0/1/2 | ❌ |

其它同期小工具：yuxiao1231/emsign_cert_update（2★，Windows `Disallowed` 和 certifi 一键修复）、sabastante/audit_aws_emudhra（3★，只查 AWS ACM 里的证书）、softwarejohely/emudhra-cert-bundle-filter（1★，只修 macOS 的 `/etc/ssl/cert.pem`）、b49nd1n/emudhra-scan 和 xiaoguan521/emudhra-scanner（0★）。另有若干利用泄露密钥做演示或 MITM 的仓库，不是扫描工具。

## 判定口径的差异

emsign-trust-scan 默认**不**报告 AAA Certificate Services。它的理由是这把根的密钥本身没有泄露，被撤销的只是它签出的交叉签名。trustsweep 会报告：只要一个不检查撤销的客户端信任 AAA，交叉签名那条链就仍然能用。事件页给 Debian、Fedora、NixOS 等系统的临时处理办法，也是把 AAA 和 emSign ECC Root CA - G3 一起取消信任。代价是会误伤 Sectigo 的合法证书，所以报告里分别列出命中的是哪个根，由用户自己判断。

## trustsweep 目前缺的

- 实际连接测试（wakumo 有）。
- 自动修复（wakumo、yuxiao1231 有）。
- 直接从 registry 拉镜像，不经过 docker。
- 读取 rpm 数据库来取版本：RPM 系统上的 bundle 能按路径归给 ca-certificates，但版本显示为未知。
- 读取二进制自身的版本：二进制只按文件名归属，版本显示为未知。

## brotlisweep 与 trailofbits/brotli-checker 的分工（2026-10-24 实查）

[trailofbits/brotli-checker](https://github.com/trailofbits/brotli-checker)（16★，10-23 发布 v0.1.0，10-24 发布 v0.2.0）是一个 coding agent 用的 skill，另附只依赖标准库的 Python 扫描器。它的做法是：比对源码指纹（20 个 decoder 文件哈希，17 个有漏洞、3 个已修复）；用 336 个编译指纹匹配 ELF 二进制里的 decoder 代码，覆盖 x86-64、x86、ARM/Thumb、AArch64、RISC-V64、PowerPC64LE、s390x、MIPS32/64（大小端）、LoongArch64，共 12 个目标；读取依赖清单（pyproject、requirements、uv.lock、Cargo.lock、go.mod 等）；判断 Node/Electron 的 fetch 能否走到 decoder；可选用 objdump 做反汇编复核。它的文档写明"PE, Mach-O, and relocatable objects are not classified by the code matcher"，也就是对 Mac 和 Windows 的二进制只做清点，不判断是否已修。

| 能力 | brotlisweep | brotli-checker |
|---|---|---|
| 判断依据 | 修复提交新增的错误码字符串，加上版本证据 | ELF 代码指纹、源码指纹、版本 |
| ELF（Linux、容器） | 按字符串判断（简单） | ✅ 代码级匹配，**更强，Linux 上优先用它** |
| Mach-O，含 universal 二进制逐 slice 判断 | ✅ | 只清点，不判断 |
| Windows PE | ✅ 按内容扫描 | 只清点，不判断 |
| Electron / Bun / Node / Deno 单文件程序 | ✅ 读二进制里的产品版本（`Electron/`、`bun-v`、`nodejs.org/download/release/v`、`Deno/`），按顺序取，避免被其中附带的 Node 版本误导 | Electron 按 reachability 指南人工复核 |
| Python Brotli、brotlicffi | ✅ 读已安装的 dist-info 版本，同时判断 `.so` 的每个 slice | 读依赖清单 |
| "这个 Python 环境会自动发 `Accept-Encoding: br`"提示 | ✅ 同一 site-packages 下有 urllib3、requests、httpx、aiohttp 时给出提示（已对照 urllib3 2.7.0、httpx 0.28.1、aiohttp 3.13.3 的源码确认） | ❌（仓库里检索 urllib3 只命中 uv.lock） |
| 源码 / 调用链分析 | ❌ | ✅（借助 Trailmark） |
| 输出 | text、JSON、SARIF，退出码 0/1/2 | text、JSON，退出码 0/1/2/3 |

两者的判定口径都很保守：brotli-checker 不会仅凭版本字符串就把二进制判为已修；brotlisweep 的 FIXED 只代表"修复后新增的字符串在里面"，UNFIXED 必须同时满足"缺标记"和"版本早于修复版本"两个条件。

其它同类工具：shivrajem/node2shell-detect（2★）和 CompleteTech-LLC/node2shell-check（0★）只比对 Node/Bun 的版本号；TahuCryptsi/brotli-distro-check（0★）只看发行版的包版本；ossf/cve-bin-tool 和 syft 的 binary classifier 都没有 brotli 规则（来源：2026-10-24 选题报告）。
