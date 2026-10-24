# trustsweep 设计

目标：在制品里找出各自打包的 CA 库，判断它们是否仍信任已撤销的 CA，并说明属于哪个包、该升级到什么版本。离线运行，单个 Rust 二进制。

## 1. 扫描目标

| 命令 | 输入 | 说明 |
|---|---|---|
| `trustsweep scan <path>...` | 目录或单个文件 | 递归遍历，不跟随符号链接。zip 类压缩包（`.whl` `.jar` `.war` `.ear` `.zip` `.apk` `.nupkg` `.asar` 除外）和 tar 类（`.tar` `.tar.gz` `.tgz`）会在内存里展开并递归，嵌套深度上限为 4 |
| `trustsweep image <ref\|dir\|tar>` | 镜像仓库的引用（直接拉取，见 §12）、OCI layout 目录，或 `docker save` 输出的 tar；加 `--docker` 时改用本机的 `docker save` | 按顺序逐层扫描，支持未压缩、gzip 和 zstd 层 |
| `trustsweep feed update` | 无 | 从事件页 JSON 和 OneCRL 重新生成数据源，写到缓存文件 |

asar 第一版不展开，作为普通文件扫描。asar 里的文件本来就不压缩，PEM 和 DER 可以直接被找到。

## 2. 证书提取

对每个文件的字节做四种扫描，都不依赖文件名或扩展名：

1. **PEM**：找 `-----BEGIN CERTIFICATE-----` 和 `-----BEGIN TRUSTED CERTIFICATE-----`，取到对应的 END 为止。先去掉字面量 `\n`、`\r`、`\t` 转义（处理 JS 和 C 字符串里的 PEM），再只保留 base64 字符，然后解码。这样二进制里的 C 字符串（Node、Go fallback）和 JS 源码里的 PEM 都能找到。
2. **DER**：找 `30 82 LL LL 30 82` 模式，即证书 SEQUENCE 后面紧跟 tbsCertificate SEQUENCE，再用 x509-parser 严格解析，解析成功并且长度一致才算。JKS（entry 里存的就是 DER）、明文 PKCS#12（JDK 的 cacerts 不加密证书）、Bun 的 `root_certs.der`、Chromium 内置的根，都靠这一步找到。第一版不单独写 JKS 和 PKCS#12 解析器，DER 扫描已经覆盖了它们；JKS 的别名和 PKCS#12 的信任属性不读。
3. **源码字面量**：把 `"0\x82…"`、`"\x30\x82…"`、八进制 `"\60\202…"` 这类转义字节串（webpki-root-certs 的源码、生成出来的 C 头文件）解码后再做 DER 扫描；`xxd -i` 风格的 `0x30, 0x82, …` 数组也一样处理。
4. **嵌入公钥字节**：对数据源里每张带 PEM 的证书，取出它 SPKI 里的公钥 BIT STRING 内容（P-384 是 97 字节，RSA-2048 的模数约 270 字节），用 Aho-Corasick 在整个文件里一次性搜索。webpki-roots 编译进 Rust 二进制后只剩 SPKI 字节，没有完整证书，前两种扫描都找不到，只能靠这一步。如果命中位置落在某张已解析出的完整证书内部，就不再单独报告。

## 3. 指纹比对

每张证书计算两个哈希：

- `sha256`：完整 DER 的 SHA-256，用于精确匹配；
- `spki_sha256`：SubjectPublicKeyInfo DER（含外层 SEQUENCE）的 SHA-256，与 OneCRL 的 `pubKeyHash` 和 Chrome CRLSet 的口径一致。同一把密钥的交叉签名或重签证书也能匹配上。

OneCRL 里另一类条目是 `issuerName`+`serialNumber`，按"颁发者 DER + 序列号"比对。

数据源里每条记录都有一个角色：

| 角色 | 含义 | 命中后的结论 |
|---|---|---|
| `root` | 签发或交叉签名了被撤销中间 CA 的根（本次是 4 个） | **trusts**：这份库仍会接受被撤销 CA 签发的证书 |
| `revoked` | 被撤销的中间 CA 本身（本次的 16 张，加上 OneCRL 的其余条目） | **contains-revoked**：库里有这张证书。它可能是信任锚，也可能只是一份阻止列表或一条证书链，需要人工确认 |

## 4. 包和修复版本的映射

先确定文件属于哪个包，按顺序尝试下面的规则，第一条命中就停：

1. **Python**：同一个 `site-packages` 下各个 `*.dist-info/RECORD` 列出的文件归属；版本取 dist-info 目录名。wheel 内部也是这样处理。
2. **npm**：路径里最后一个 `node_modules/<name>`（或 `@scope/name`），版本取那一层的 `package.json`。
3. **Maven**：jar 里的 `META-INF/maven/<g>/<a>/pom.properties`。
4. **JDK**：`.../lib/security/cacerts`，版本取 JDK 根目录 `release` 文件里的 `JAVA_VERSION`。
5. **dpkg**：`/var/lib/dpkg/info/<pkg>.list` 和 `/var/lib/dpkg/status`；distroless 镜像没有这两个文件，改用 `status.d/<pkg>` 和 `status.d/<pkg>.md5sums`；`/etc/ssl/certs/ca-certificates.crt` 是生成出来的文件，不在任何 .list 里，直接归给 ca-certificates。
6. **apk**：`/lib/apk/db/installed`，其中 `P:` 是包名，`V:` 是版本，`F:` 是目录，`R:` 是文件。
7. **RPM 系**：`/etc/pki/ca-trust/extracted/...` 和 `/etc/pki/tls/certs/ca-bundle.crt` 按路径归给 ca-certificates。rpm 数据库是 sqlite，不解析，所以版本显示为未知。
8. **Homebrew**：路径中的 `Cellar/<pkg>/<ver>/`。
9. **二进制**：文件名匹配数据源里的 `binaries` 字段（node、bun、deno、uv、electron 等），版本标为未知。

然后用 `(ecosystem, name)` 去查数据源的 `fixes` 表。修复版本来自事件页的 "Who has patched" 表，每条都记了来源 URL。第一版**不做版本比较**：只要证书确实在文件里，就足以说明问题；版本号只用来提示"升级到下列版本之一"。之所以不比较，是因为各生态的版本格式差别很大（Debian 有 `~deb12u2` 这样的写法），而且已经升过级的环境里仍可能留着旧的自带副本，这时证书在不在才是准确的判断依据。

## 5. 容器镜像的层处理

- 逐层扫描，每条发现都记下层号和层的 digest。
- 后面的层如果有同路径的文件，或者有 `.wh.<name>`、`.wh..wh..opq` 这样的 whiteout 删除了它，前面那层的发现就标为 `superseded`。这类发现照常输出，但不计入失败。
- 包数据库（dpkg、apk）取最后一层的版本，并且只取没被删除的那份。

## 6. 输出

- **终端**（默认）：按文件分组，显示文件路径、所在层、命中的证书名、结论、所属包和版本、建议升级到的版本。
- **JSON**（`--format json`）：结构和终端一致，同时带上数据源的 id 和生成时间。
- **SARIF 2.1.0**（`--format sarif`）：每个数据源条目对应一条 rule；trusts 级别为 `error`，contains-revoked 级别为 `warning`；位置是 `artifactLocation.uri` 加上字节偏移。可以接 GitHub Code Scanning。

退出码：1 表示至少有一条未被覆盖的 trusts 级别发现；没有这类发现但扫描不完整（有文件读取失败或超过上限）时为 2；运行出错（数据源无法解析、镜像无法读取）也是 2；其余情况为 0。

## 7. 误报控制

- 只报告数据源里列出的证书。正常的根证书不会被当成问题。
- 区分 `trusts` 和 `contains-revoked`（见 §3）：吊销列表、证书链文件、测试夹具里出现被撤销的中间证书，只算 warning，不导致失败。
- 同一个文件里只有 1 张证书时，标为 `single-cert`。它可能是测试夹具或文档示例，而不是信任库；仍然报告，但结论降为 warning。
- jar 签名块（`META-INF/*.RSA`、`*.DSA`、`*.EC`）里是签名者的证书链，不计入 CA bundle 统计。
- trustsweep 自己的二进制内嵌了数据源，扫描时跳过它，并计入 `excluded`。
- 支持 `--exclude <glob>`（可多次），glob 对展开后的完整路径匹配，例如 `**/tests/**`。
- 被后续层覆盖或删除的镜像文件标为 `superseded`（见 §5）。
- 拉取数据源失败时直接报错退出，**不会**静默退回内置的旧数据。正在使用的数据源 id 和生成时间会出现在每次输出里。
- 读不了的文件（权限、超过上限）会计数，并在输出中列出，不会默默跳过。超过上限（默认 1 GiB）的文件会报错并跳过，计入 `errors`。

## 8. 与 argus 的关系

argus-archive 是"解压到磁盘"的模型，而且没有发布到 crates.io。trustsweep 需要的是不落盘、在内存里递归，所以第一版不依赖它，自己用 `zip`、`tar`、`flate2` 实现。沿用了它的两点做法：限制条目数和单条目大小，不跟随符号链接。

如果后面要把 trustsweep 做成 argus 的子命令，可以把 `scan::Scanner` 和 `feed` 拆成一个 lib crate，供 argus-cli 调用。第一版先保持单 crate。

## 9. 数据源格式（`data/feed.json`）

```json
{
  "id": "emudhra-2026-10",
  "generated_at": "2026-10-22T...",
  "sources": ["https://emudhra.we-have-a-problem.com/impacted-intermediates.json", "..."],
  "certs": [
    {"name": "emSign ECC Root CA - G3", "role": "root", "sha256": "...", "spki_sha256": "...", "pem": "..."},
    {"name": "EM DV TLS CA - G3B", "role": "revoked", "sha256": "...", "spki_sha256": "...", "pem": "..."}
  ],
  "onecrl": [{"subject": "...", "pub_key_hash": "..."}, {"issuer": "...", "serial": "..."}],
  "fixes": [{"ecosystem": "pypi", "name": "certifi", "fixed": ["2026.10.19"], "source": "https://..."}],
  "binaries": [{"file": "bun", "ecosystem": "generic", "name": "bun"}]
}
```

内置数据源用 `include_str!` 编进二进制。`feed update` 把新版本写到 `$XDG_CACHE_HOME/trustsweep/feed.json`（macOS 上是 `~/Library/Caches/trustsweep/feed.json`）。只要这个文件存在，就优先使用它；也可以用 `--feed` 显式指定。`fixes` 和 `binaries` 是人工维护的，`feed update` 会原样保留，只刷新 `certs` 和 `onecrl`。

## 10. 第一版不做的事

rpm 数据库、Go buildinfo 解析、asar 和 Flatpak 的专门解析、版本比较。registry 拉取和 CCADB 已在后续版本补上，见 §12、§13。

## 11. brotlisweep 子命令（CVE-2026-111497）

- 复用同一套遍历方式（目录、压缩包、镜像层、whiteout）和同一套包归属逻辑，只把"找证书"换成"找 Brotli decoder"。数据放在 `data/brotli.json`，内置进二进制。
- 每个文件先识别 Mach-O universal 头（`0xcafebabe` / `0xcafebabf`，slice 数少于 30，用来排除 Java class 文件），再对每个 slice 分别统计对照串 `ERROR_FORMAT_EXUBERANT_NIBBLE` 和修复标记 `ERROR_FORMAT_BLOCK_SWITCH`。两种串都没有的文件不报告。
- 版本证据有两个来源，优先用包元数据（PyPI Brotli、brotlicffi 的 dist-info）。没有包元数据时，读二进制里写的产品版本，按 bun、electron、deno、node 的顺序取第一个匹配的产品，同一产品出现多个版本时取出现次数最多的。修复版本按分支前缀匹配，例如 Node 22 的修复版本是 22.23.4。
- 判定：有标记就是 fixed；没有标记、且版本早于所在分支的修复版本，才是 unfixed；其余情况都是 unknown。所以"找不到标记"本身永远不会被判成 unfixed。
- 退出码：存在未被覆盖的 unfixed 时为 1；扫描不完整时为 2；其余为 0。SARIF 用 `brotli-unfixed`（error）和 `brotli-unknown`（warning）两条规则。

## 12. 直接从镜像仓库拉取

- 引用格式：`alpine`、`alpine:3.20`、`ghcr.io/o/r:tag`、`host:port/r@sha256:…`。没写 registry 时默认是 Docker Hub（`registry-1.docker.io`），单段名称会补成 `library/<name>`。
- 先请求 `GET /v2/<repo>/manifests/<ref>`，Accept 头同时声明 OCI 和 Docker v2 的 index 与 manifest 类型。收到 401 时，按 `WWW-Authenticate` 的指示处理：Bearer 方式去 realm 拿 token，默认匿名，有凭据时带上 Basic；Basic 方式直接用凭据。
- 凭据来源依次是：环境变量 `TRUSTSWEEP_REGISTRY_USERNAME` / `TRUSTSWEEP_REGISTRY_PASSWORD`；`$DOCKER_CONFIG/config.json` 或 `~/.docker/config.json` 里 `auths` 下的 `auth`。不执行 credential helper。ureq 遇到跨主机重定向时不转发 Authorization 头，所以 CDN 拿不到凭据。
- 拉到的是多架构 index 时，按 `--platform` 选（默认是本机 CPU 对应的 linux 架构）；找不到匹配的平台就报错，并列出 index 里有哪些平台。
- 每个 manifest 和每个层都要校验 sha256 digest。层先写进临时目录、校验通过后再交给现有的逐层扫描。带 `urls` 的 foreign layer 不下载，直接报错。
- OCI layout 目录走同一套流程（`index.json` → manifest → 层），测试就用它代替网络。

## 13. 数据源泛化

`feed update` 每次全量重建，三个来源缺一个就报错退出：

| 来源 | 格式 | 进入数据源的内容 | 角色 |
|---|---|---|---|
| Mozilla OneCRL（Remote Settings changeset） | JSON | `enabled` 的条目：`subject`+`pubKeyHash`，或 `issuerName`+`serialNumber` | `revoked` |
| CCADB Mozilla Removed CA Certificate Report | CSV（带 BOM，每个字段都有引号） | `Valid To` 晚于当天的根：名称、SHA-256、`NSS Release When Removed`、移除 bug | `removed` |
| 事件数据（目前是 eMudhra） | JSON，含 PEM | 被攻破的中间 CA 和它们链到的根 | `revoked`、`root` |

- CSV 按表头里的列名取值，列名对不上就报错，不会悄悄读错列。
- `removed` 只按证书 SHA-256 匹配，因为报告里没有 PEM，也就没有公钥字节可搜。和事件根重复的（例如 emSign ECC Root CA - G3）以事件根为准。
- 判定：`removed` 命中算 REVIEW，不算失败，因为报告不区分"出了问题被取消信任"和"CA 自己退役"。事件根命中仍是 TRUSTS。文本输出把一个文件里命中的 removed 根合并成一行，JSON 里逐条列出。
