# trustsweep 调研

调研时间：2026-10-22。除非另有标注，每条事实都在当天对原始来源实查过；查不到的写"未核实"。

## 1. eMudhra 中间 CA 事件

### 1.1 时间线

| 时间（UTC） | 事件 | 来源 |
|---|---|---|
| 2025-04-30 | 8 个中间 CA 签发（`not_before` 为 2025-04-30），密钥从签发起就可以被恢复 | impacted-intermediates.json；事件页 "since the certificates were created in April 2025" |
| 2026-10-17 18:05 / 20:06 | 报告人 Wayne 用 8 把私钥各签了一条消息 "We have a problem here - Wayne"，发给各根证书计划。Chrome 记录的时间是 18:05，Mozilla 记录的是 20:06 | 事件页；Mozilla dev-security-policy 帖 |
| 2026-10-17 19:45 | Chrome 通过 CRLSet 按 SPKI 哈希屏蔽 | dev-security-policy 帖 |
| 2026-10-17 22:59 | Firefox 通过 OneCRL 屏蔽 | dev-security-policy 帖 |
| 2026-10-18 09:24–09:38 | eMudhra 撤销 8 张直签中间证书（reason `ca_compromise`） | impacted-intermediates.json 的 `revocation.date` |
| 2026-10-19 | Apple 设备开始屏蔽；事件通报给下游信任库 | 事件页 |
| 2026-10-19 10:35:36 | Sectigo 撤销 8 张交叉签名（由 AAA Certificate Services 签发） | impacted-intermediates.json |
| 2026-10-20 | Microsoft 平台开始屏蔽；Mozilla 发布 NSS 更新，移除签发这些中间 CA 的根 | 事件页；dev-security-policy 帖 |

- CVE：CVE-2026-111943。来源是 Go 安全公告和 Chainguard 的通告页 `images.chainguard.dev/security/CVE-2026-111943`。
- Mozilla 事件 bug：[2083449](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449)。OneCRL 条目引用的是 bug 2083382，CCADB 移除记录引用的是 bug 2084101。
- 原因：CA 生成密钥时出错，任何人都能从证书本身恢复私钥。Google 的说法是"随机性不足"，eMudhra 的说法是生成证书的脚本有错。有二手来源（tech-insider、0xAJStrike/emsign-trust-scan 的 README）称私钥标量是 4、56、66 等小整数，**未核实**。
- 事件页称，这段时间内 CT 日志里没有这些中间 CA 签出的证书，所以强制 CT 的浏览器不会被攻击。浏览器之外的大量客户端不检查 CT。

### 1.2 受影响证书

8 个中间 CA，每个有两张证书：一张由 eMudhra 根直签，一张由 Sectigo 的 AAA Certificate Services 交叉签名，共 16 张。其中 6 个用于 TLS，2 个用于代码签名。

| 中间 CA | 用途 | 直签证书 SHA-256 前缀 | 交叉签名证书 SHA-256 前缀 |
|---|---|---|---|
| EM DV TLS CA - G3B | tls | 42C4ACCD12C4F595 | 45A883F349AEDFD5 |
| EM OV TLS CA - G3B | tls | 98B896625C0C230A | 5F1DED4DD590AF74 |
| EM EV TLS CA - G3B | tls | E7568FE6E12331F4 | 579480AEA166290B |
| EM DV TLS CA - G3C | tls | 0164D7CEAE5BB909 | 62B7F9868263F72F |
| EM OV TLS CA - G3C | tls | CB6E15165AC802E9 | 7485B51C0ED19287 |
| EM EV TLS CA - G3C | tls | 432EC25F0D28DE90 | FD9D5C2DBBD4995A |
| EM OV CS CA - G3B | code-signing | 9E39DE2881273ACC | A496E23AC0CAB815 |
| EM OV CS CA - G3C | code-signing | 4B2460A466F95FD4 | 84112972B8E59D14 |

完整指纹、SPKI 哈希和 PEM 见 [`data/feed.json`](../data/feed.json)，它由事件页的 `impacted-intermediates.json` 原样生成。

它们链到的 4 个根（摘自 `roots.json`）：

| 根 | 角色 | SHA-256 | 各根证书计划的状态 |
|---|---|---|---|
| emSign Root TLS CA - G3 | 直接签发者 | 7DD78D5F4F13459A83DFF9ABBBA62EDBAF6F2D102BF257FD712F4D9F2746ED8D | 只有 Microsoft 收录 |
| emSign Root CS CA - G3 | 直接签发者 | F2EDAAFF3D9B701FB4D14C9F285F8C0BAD90FC3BCC1FA07D47F4718EDABA34A5 | 只有 Microsoft 收录 |
| AAA Certificate Services（Sectigo/Comodo） | 交叉签名签发者 | D7A7A0FB5D7E2731D771E9484EBCDEF71D5F0C3E0A2948782BC83EE0EA699EF4 | Apple、Microsoft 收录；Mozilla、Chrome 标为 Removed |
| emSign ECC Root CA - G3 | 给 emSign Root TLS CA - G3 做交叉签名 | 86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B | 四家都收录 |

对扫描工具来说，结论是：**自带的 CA 库里装的是根，不是中间 CA**。一份库只要还含 emSign ECC Root CA - G3 或 AAA Certificate Services（或上面两个 emSign G3 根），又不检查撤销，就仍会接受由这 8 个中间 CA 签发的证书。

补充核实：

- CCADB 的 Mozilla Included 报告里，AAA Certificate Services 现在的 Trust Bits 只有 `Email`，所以从 NSS 里只提取 TLS 根的 PEM 库（certifi、curl）本来就不含它。Java cacerts、Apple、Microsoft 这类不按 Mozilla 信任位过滤的库会含它。
- CCADB 的 Removed 报告记录 emSign ECC Root CA - G3 的移除版本是 "3.132"（bug 2084101），事件页写的修复版本是 NSS 3.131.1。两者不一致，**未核实**哪个准确。

### 1.3 各项目的修复方式（实查）

| 项目 | 做法 | 来源 |
|---|---|---|
| certifi（Python） | 2026.10.18 移除了 4 个 emSign 根（G1、ECC G3、C1、ECC C3）；2026.10.19 又把 G1、C1、ECC C3 加了回来。最终只移除 **emSign ECC Root CA - G3** | python-certifi 提交 5cb238c、662df63 |
| webpki-roots / webpki-root-certs（Rust） | 1.0.10 移除 emSign ECC Root CA - G3 | rustls/webpki-roots 提交 c644e3e |
| curl CA bundle | 2026-10-20 版只剩 emSign Root CA - G1 一个 emSign 根 | curl.se/ca/cacert.pem（Last-Modified 2026-10-20 13:32:40 GMT） |
| Node.js | "crypto: update root certificates to NSS 3.131.1"（v24.22.1 发布说明） | nodejs/node releases |
| Go | crypto/x509 屏蔽这几个中间 CA，Verify 会过滤掉含它们的链。公告没有提到根或 x509roots/fallback | golang-announce 帖 66pojueaQek |
| Bun | PR [oven-sh/bun#46159](https://github.com/oven-sh/bun/pull/46159) 在 2026-10-20 合入，`root_certs.der` 里的证书从 121 张减到 117 张。到 2026-10-22，最新的正式版仍是 bun-v1.4.3（10-10 发布），**尚未发版** | GitHub API |
| Windows | 通过自动证书信任列表更新下发；事件页提供脚本，把 16 张证书导入 `LocalMachine\Disallowed` | 事件页 |
| macOS | 系统会屏蔽这些证书，但 `/etc/ssl/cert.pem` 没有更新；系统自带的 curl、git、python3 不检查撤销 | 事件页 |

事件页的 "Who has patched" 表（2026-10-22 抓取）列出了以下修复版本，trustsweep 用它给出升级建议：Ubuntu、Debian、Alpine `20261020-r0`、Fedora、Arch、Gentoo、FreeBSD 等发行版的 ca-certificates；NSS 3.131.1；Go 1.27.3 和 1.26.10；Java 8u511、11.0.33、17.0.21、21.0.13、25.0.5、27.0.1；Node.js 22.23.4、24.22.1、26.12.1；certifi 2026.10.19；pip 26.2.2；uv 0.13.4；pixi 0.82.1；rustls-webpki 0.103.16；webpki-roots 1.0.10；Rustup 1.29.2；Electron 44.9.1、43.8.1、42.11.16；Deno 2.9.8；Claude Code 2.1.303；Composer ca-bundle 1.4.16 和 1.6.0；Elixir castore 1.0.22；Perl Mozilla::CA 20261020；mise 2026.10.17；Homebrew ca-certificates 2026-09-25_1。仍为 pending 的有：Bun、Erlang certifi、Bottlerocket。各版本号以事件页为准，trustsweep 没有逐个打开对应项目的发布页复核，只抽查了 certifi、webpki-roots、Node 和 Bun。

### 1.4 可以自动更新的数据源

| 数据源 | 地址 | 格式 | 内容 | 实测 |
|---|---|---|---|---|
| 事件页 JSON | `https://emudhra.we-have-a-problem.com/impacted-intermediates.json`、`roots.json`；源码在 [galadran/we-have-a-problem.com](https://github.com/galadran/we-have-a-problem.com)（209★，2026-10-19 建） | JSON，含 PEM、sha256、spki_sha256、撤销日期 | 16 张中间证书和 4 个根 | 可下载，结构稳定，**trustsweep 的主数据源** |
| Mozilla OneCRL | `https://firefox.settings.services.mozilla.com/v1/buckets/security-state/collections/onecrl/changeset?_expected=0` | Remote Settings JSON，两种条目：`issuerName`+`serialNumber`（base64 DER），或 `subject`+`pubKeyHash`（SPKI SHA-256 的 base64） | 共 1907 条，包括本次的 16 条（`subject`+`pubKeyHash` 形式，bug 2083382） | 可下载；`pubKeyHash` 和 impacted-intermediates.json 的 `spki_sha256` 一致（例如 G3B 的 `6+1kdc…` = `EBED6475…`） |
| CCADB Mozilla Removed 报告 | `https://ccadb.my.salesforce-sites.com/mozilla/RemovedCACertificateReportCSVFormat` | CSV，含 SHA-256 和 "Subject + SPKI SHA256" | 159 行，已移除的根 | 可下载；不含 PEM，只能按指纹比对 |
| CCADB Mozilla Included 报告 | `.../mozilla/IncludedCACertificateReportPEMCSV` | CSV，含 PEM 和 Trust Bits | 当前收录的根 | 可下载；可以用来判断一个根有没有 TLS 信任位 |
| Chrome CRLSet | — | 二进制 | 按 SPKI 屏蔽 | 未接入，格式未核实 |

## 2. 各生态自带 CA 库的常见形态

| 生态 | 位置或形态 | 编码 | 怎么判断属于哪个包 |
|---|---|---|---|
| Python certifi | `site-packages/certifi/cacert.pem` | PEM，带 `# Label:` 注释 | 同目录的 `certifi-*.dist-info`（RECORD 里列了这个文件） |
| pip 自带 | `site-packages/pip/_vendor/certifi/cacert.pem` | PEM | `pip-*.dist-info` 的 RECORD |
| 其它 wheel | 例如 botocore 的 `cacert.pem`，以及 [stripe-ruby #2001](https://github.com/stripe/stripe-ruby/issues/2001) 这类各自带一份 CA 文件的 SDK | PEM | wheel 内 dist-info 的 RECORD |
| Node.js | 编译进 `node` 可执行文件（`node_root_certs.h`，是 C 字符串形式的 PEM） | 二进制里的 PEM 文本 | 文件名或路径 |
| npm 包 | 有些包在 JS 里带 PEM 字符串，例如 `"-----BEGIN CERTIFICATE-----\n..."` 这种带转义的写法 | JS 字符串 | 最近一层 `node_modules/<pkg>/package.json` |
| Bun | `root_certs.der` 编译进 `bun` 可执行文件（PR #46159） | 连续的 DER | 文件名 |
| Deno | Rust 实现，用 webpki-roots 一类的库（具体是哪个 crate，**未核实**） | 原始 SPKI 字节 | 文件名 |
| Rust（rustls） | webpki-roots 把每个根存成 `TrustAnchor { subject, subject_public_key_info }`，只保留去掉外层 SEQUENCE 的 SPKI，**不含完整证书**；webpki-root-certs 存的是完整 DER | 原始 SPKI 字节 / DER | 二进制无法可靠判断，只能看文件名 |
| Go | 默认用系统信任库；引入 `golang.org/x/crypto/x509roots/fallback` 时把 PEM 编译进二进制 | 二进制里的 PEM | Go buildinfo（第一版未实现） |
| Java | `$JAVA_HOME/lib/security/cacerts`，老版本是 JKS（magic `FEEDFEED`），新版本是 PKCS#12，证书不加密 | JKS / PKCS#12 里的 DER | JDK 根目录的 `release` 文件（`JAVA_VERSION=`） |
| Jar | 包内可能带 `.pem`、`.crt`、`.jks` | 任意 | `META-INF/maven/*/*/pom.properties` |
| Debian / Ubuntu | `/etc/ssl/certs/ca-certificates.crt`（生成文件）、`/usr/share/ca-certificates/mozilla/*.crt` | PEM | `/var/lib/dpkg/info/*.list` + `/var/lib/dpkg/status`；生成出来的 bundle 不在任何 .list 里，按路径归给 ca-certificates |
| Alpine | `/etc/ssl/certs/ca-certificates.crt`、`/etc/ssl/cert.pem`（ca-certificates-bundle） | PEM | `/lib/apk/db/installed` |
| RHEL / Fedora | `/etc/pki/ca-trust/extracted/...` | PEM / JKS / p11-kit | rpm 数据库是 sqlite，第一版不解析 |
| Flatpak runtime | runtime 里自带一份 ca-certificates（Freedesktop SDK 25.08.19 和 26.08.3 已修复） | PEM | runtime 名称和版本（第一版只按文件扫描） |
| Homebrew | `/opt/homebrew/Cellar/ca-certificates/<ver>/share/ca-certificates/cacert.pem`，以及 `openssl@3` 用的 `cert.pem` | PEM | Cellar 路径里的包名和版本 |
| Electron / Chromium | Chrome Root Store 编译进二进制 | DER | 文件名（第一版只认 `electron`） |
| macOS 系统 | `/etc/ssl/cert.pem` | PEM | 系统文件 |

## 3. 竞品与查重

关键词拆了 10 组，用 `gh search repos --sort stars` 搜，star 数是 2026-10-22 实查的。

| 关键词 | 最高命中 |
|---|---|
| "embedded ca bundle scanner" | 无结果 |
| "ca certificates scan binaries" | 无结果 |
| "distrusted root certificate scan" | 无结果 |
| "cacert.pem outdated" | 无结果 |
| "certificate inventory cli" | 无结果 |
| "trust store scanner container" | 无结果 |
| "ca bundle audit" | cbeer/capistrano-bundle_audit 0★（无关） |
| "emudhra scan" | b49nd1n/emudhra-scan 0★、xiaoguan521/emudhra-scanner 0★（10-21、10-22 建） |
| "emsign" | yuxiao1231/emsign_cert_update 2★（Python，只审计和修主机信任库） |
| 已知项目 | 0xAJStrike/emsign-trust-scan 2★（Python，盘点主机信任库，写死本次事件的 IOC）；git-pkgs/certs 1★（Go，见下） |

**git-pkgs/certs** 最接近：Go 库加 CLI，能盘点 PEM、DER、JKS、PKCS#12，扫 wheel、jar、tar 和各种压缩格式，输出 JSON Lines，可以和已知的 certifi、curl 快照比对来源。但它明确说明"证书存在不代表应用在用、也不代表有漏洞"，**不给"是否信任已撤销 CA"的结论**，不按层扫容器镜像，不找 webpki-roots 那种只存 SPKI 的嵌入形式，也不给升级建议和 SARIF 输出。

大玩家：

- **syft**：[#5451](https://github.com/anchore/syft/issues/5451) "Container images bundle CA roots distrusted after the eMudhra/Sectigo incident"（2026-10-21 开，open，0 评论）；[#5191](https://github.com/anchore/syft/issues/5191) "inventory X.509 certificates for CycloneDX CBOM"（2026-08-17 开，open）。也就是说 syft 目前还不盘点证书。
- **grype**：搜 "emudhra"，0 个 issue。
- **trivy**：搜 "emudhra" 只命中一个无关的已关闭 PR（#7100）；搜 "certificate bundle"，0 个 issue。trivy 的 secret 扫描能找私钥，但不比对 CA 库。**未发现**它有 CA 库扫描功能。
- **nixpkgs**：[#576542](https://github.com/NixOS/nixpkgs/issues/576542) "Tracking: CA bundles inside wheels, jars and zips"（open，0 评论）。

结论：没有工具能同时做到"在任意制品里找 CA 库、对照撤销清单给结论、指出属于哪个包和该升到什么版本"。窗口在于 syft 和 trivy 还没合入相关功能。

## 4. argus 能复用什么

[argus](https://github.com/majiayu000/argus)（Rust workspace，0.3.0）里最相关的是 `argus-archive`。它把 tar.gz 和 ZIP 解压到磁盘，带路径安全检查和条目数、路径长度上限，也有 `extract_zip_to_memory`。但：

1. 它没有发布到 crates.io（`cargo search argus-archive` 无结果），只能用 path 或 git 依赖，会把 trustsweep 绑在 argus 仓库上；
2. trustsweep 需要的是"逐条目读进内存、嵌套递归、不落盘"，而 argus-archive 是"解压到目录"的模型。

所以第一版不直接依赖 argus，只沿用它的思路：条目数和大小上限，以及不跟随符号链接。见 design.md §8。
