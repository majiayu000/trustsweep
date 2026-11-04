# 修复版本逐条实物核实（2026-11-05）

`data/feed.json` 的 `fixes` 表是人工维护的。v0.2.0 发布后，有一次独立实测发现其中 certifi 和 pip 两条给错了：certifi 2026.10.19 又把 emSign 的根加了回去，pip 26.2.2 自带的就是这个版本的 certifi。所以这里把全部 31 条重新核实了一遍。

**方法**：下载每条"修复版本"对应的实际发布物（wheel、crate、npm tgz、hex/CPAN tarball、.deb/.apk/.rpm、release 里的二进制、JRE），用当前的内置数据源跑 `trustsweep scan`。只有没有任何发现（既没有 TRUSTS，也没有 REVIEW）才算"干净"。CCADB 中 Mozilla 已移除的根也要算在内，其中包括这次事件里 NSS 3.131 一并移除的 emSign Root CA - C1 和 emSign ECC Root CA - C3。如果修复是代码层面的改动（Go、rustls-webpki），或者文件格式 trustsweep 解析不了（NSS certdata.txt），就读源码或按 label 核对，表里会写明。每条的核实说明也写进了 feed 的 `verified` 字段。

**核实中顺带修的误报**：uv、pixi、mise、deno 这类 Rust 程序会把 rustls-webpki 的 `distrusted/*.spki.der`（8 个被攻破的中间 CA 公钥）编进二进制，这是阻止列表，不是信任锚。以前它们会被报成"含被撤销的 CA"（REVIEW）。现在，被撤销的 CA 如果只以裸公钥的形式出现，就不再报告。

| 条目 | 原修复版本 | 核实结果 | 改为 |
|---|---|---|---|
| pypi certifi | 2026.10.19 | 2026.10.18 干净；2026.10.19 加回 C1、C3、G1（REVIEW）；2026.10.23 干净，是最新版 | **2026.10.23** |
| pypi pip | 26.2.2 | 26.2.2 自带 certifi 2026.10.19（REVIEW）；26.3 干净 | **26.3** |
| pypi uv / generic uv | 0.13.4 | 0.13.4 至 0.13.7 已去掉 G3，但都还含 C1、C3（REVIEW），目前没有完全干净的版本 | 不变，注明 |
| generic pixi | 0.82.1 | 0.82.1 和 0.83.0 含 C1、C3；0.84.0 和 0.84.1 干净 | **0.84.0** |
| cargo webpki-roots | 1.0.10、0.26.11 | 1.0.10 含 C1、C3；1.0.11 干净；0.26.11 是转发到 1.x 的空壳 | **1.0.11**、0.26.11 |
| cargo webpki-root-certs | 1.0.10、0.26.11 | 同上 | **1.0.11**、0.26.11 |
| cargo rustls-webpki | 0.103.16 | crate 干净，自带 8 个被撤销中间 CA 的公钥阻止列表 | 不变 |
| generic rustup | 1.29.2 | rustup-init（aarch64-apple-darwin）干净 | 不变 |
| generic node | 22.23.4、24.22.1、26.12.1 | 24.22.1 和 26.12.1 干净；22.23.4 不含 eMudhra 根，但还含 ePKI Root（Mozilla 在 NSS 3.126 移除），判 REVIEW，它已是 22.x 的最新版 | 不变，注明 |
| npm / generic electron | 44.9.1、43.8.1、42.11.16 | 不能按内容核实：44.9.1 和 43.8.1 仍带 G3 和 AAA，修复在 Chromium 的中间 CA 阻止列表里；三个版本都带 Mozilla 已移除的根（Chromium 有自己的根证书计划） | 不变，注明 |
| generic bun | （待定） | 1.4.4 干净 | **1.4.4** |
| generic deno | 2.9.8 | 去掉了 G3，带阻止列表，但还含 C1、C3；2.9.8 是最新版 | 不变，注明 |
| generic claude-code、npm @anthropic-ai/claude-code | 2.1.303 | 2.1.303 原生二进制仍含 emSign ECC Root CA - G3，changelog 只写了"Bug fixes"；2.1.304、2.1.305、2.1.307、2.1.311、2.1.318 干净；npm 包本身不含证书库 | **2.1.304** |
| generic mise | 2026.10.17 | 2026.10.21 及以前含 C1、C3；2026.10.22 至 2026.11.0 干净 | **2026.10.22** |
| generic go | 1.27.3、1.26.10 | 代码修复：两个版本 `crypto/x509/verify.go` 里的 `distrustedSPKIHashes` 都有 8 个公钥 | 不变 |
| java jdk | 27.0.1、25.0.5、21.0.13、17.0.21、11.0.33、8u511 | Temurin 27.0.1.0.2、25.0.5、21.0.13、17.0.21 干净；11.0.33 和 8u511 还没有 Temurin 构建，未用实物核实 | 不变，注明 |
| deb ca-certificates | 7 个版本 | 都不含 G3 和 AAA；deb12u2、deb13u1 仍带 23 个 Mozilla 后来移除的根，nmu1 和四个 Ubuntu 版本仍带 C1、C3，都判 REVIEW，各自已是所在 suite 的最新 | 不变，注明 |
| deb ca-certificates-java | （无） | 没有可核实的修复版本 | 不变 |
| apk ca-certificates、ca-certificates-bundle | 20261020-r0 | edge、v3.22、v3.21、v3.20（aarch64）都干净 | 不变 |
| brew ca-certificates | 2026-09-25_1 | 按 formula 核对（没下载 bottle）：2026-09-25_1 只按 SPKI 去掉了 3 个事件根，仍含 C1、C3；2026-10-20 用的是 curl 2026-10-20 的包，干净 | **2026-10-20** |
| hex castore | 1.0.22 | 干净 | 不变 |
| hex certifi | （待定） | 2.18.0（10-23）干净 | **2.18.0** |
| packagist composer/ca-bundle | 1.4.16、1.6.0 | 都干净 | 不变 |
| cpan Mozilla-CA | 20261020 | 不含 eMudhra 根，但含 C1、C3；20261020 已是最新 | 不变，注明 |
| generic nss | 3.131.1 | certdata.txt 按 label 核对：emSign 只剩 G1，没有 AAA | 不变 |
| generic curl-ca-bundle | 2026-10-20 | 干净 | 不变 |
| rpm ca-certificates | 2026.2.92_v9.0.319 | Fedora 44、45、46 的包都不含 G3 和 AAA；p11-kit 源里仍有 Mozilla 已移除、但被限定为邮件或代码签名用途的根，判 REVIEW | 不变，注明 |

**输出逻辑的兜底**：如果被扫描对象的版本已经大于或等于它所在分支的修复版本，却仍然不干净，就不再建议"升级到某某版本"，而是提示"已是修复版本仍不干净，请升级到最新版或人工复查"。版本号无法按数字比较的（例如 Debian 的 `~deb12u2`），继续给出原来的建议。
