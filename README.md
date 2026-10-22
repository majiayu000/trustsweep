# trustsweep

[![CI](https://github.com/majiayu000/trustsweep/actions/workflows/ci.yml/badge.svg)](https://github.com/majiayu000/trustsweep/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/majiayu000/trustsweep)](https://github.com/majiayu000/trustsweep/releases/latest)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**trustsweep scans venvs, node_modules, wheels, jars, container images and single-file binaries for bundled CA certificate stores (certifi, pip, Node, Bun, Deno, uv, Java cacerts, Alpine/Debian ca-certificates) that still trust a revoked CA, such as the October 2026 eMudhra intermediate CA compromise (CVE-2026-111943), and tells you which package to upgrade.**

Patching the OS trust store does not reach the copies of the CA bundle that pip, Node, Bun, Deno, uv, Java and many SDKs ship themselves. Vulnerability scanners that work from an SBOM or lockfile only catch packages that have an advisory, such as certifi or webpki-roots. trustsweep reads the bytes instead. It finds PEM, DER, JKS, PKCS#12, escaped source literals and the bare root keys that webpki-roots compiles into Rust binaries, and matches them against the incident data and Mozilla OneCRL. It runs offline as a single binary.

## Install

Download a prebuilt binary (macOS arm64, macOS x86_64 or Linux x86_64) from [Releases](https://github.com/majiayu000/trustsweep/releases/latest), or build it with cargo:

```bash
cargo install --git https://github.com/majiayu000/trustsweep
```

## Usage

```bash
trustsweep scan .venv node_modules ~/.local/bin app.jar   # files, directories, archives
trustsweep image python:3.12-alpine                       # container image, layer by layer (uses `docker save`)
trustsweep scan . --format sarif -o trustsweep.sarif      # GitHub Code Scanning
trustsweep feed update                                    # refresh revoked-CA data from the incident JSON + OneCRL
```

Exit code `1` means a live CA bundle still trusts a revoked CA. Exit code `2` means the scan was incomplete or failed. Exit code `0` means neither.

## Real output

`trustsweep image python:3.12-alpine` (`sha256:4c47124a8391…`, 2026-10-22):

```
TRUSTS     /etc/ssl/certs/ca-certificates.crt
           layer 1 (sha256:dfaaa230ea7e)
           trust store contains a root that issued or cross-signed a revoked CA (121 certs in file)
           - emSign ECC Root CA - G3 [root, feed, matched by sha256 at byte 175616]
           package: apk ca-certificates-bundle 20260909-r0  (from /lib/apk/db/installed)
           fix: upgrade to 20261020-r0 (https://emudhra.we-have-a-problem.com/#developers)

TRUSTS     /usr/local/lib/python3.12/site-packages/pip/_vendor/certifi/cacert.pem
           layer 2 (sha256:322376317f03)
           trust store contains a root that issued or cross-signed a revoked CA (151 certs in file)
           - AAA Certificate Services [root, feed, matched by sha256 at byte 8285]
           - emSign ECC Root CA - G3 [root, feed, matched by sha256 at byte 182076]
           package: pypi pip 25.0.1  (from /usr/local/lib/python3.12/site-packages/pip-25.0.1.dist-info/RECORD)
           fix: upgrade to 26.2.2 (https://github.com/pypa/pip/releases/tag/26.2.2)

SUPERSEDED /etc/ssl/certs/ca-certificates.crt
           layer 0 (sha256:1b349a333453)
           ...
```

A Rust binary built with webpki-roots contains no certificates, only the root keys. trustsweep finds those too:

```
TRUSTS     ~/.local/bin/uv
           embeds the public key of a root that issued or cross-signed a revoked CA, the way webpki-roots stores trust anchors (removed in webpki-roots 1.0.10); rebuild against the fixed version (0 certs in file)
           - emSign ECC Root CA - G3 [root, feed, matched by embedded-key at byte 35634726]
           package: generic uv version unknown  (from executable named uv)
           fix: upgrade to 0.13.4 (https://github.com/astral-sh/uv/releases/tag/0.13.4)
```

The scans in [`examples/`](examples/) found affected bundles in certifi 2026.2.25, grpcio 1.78.0 (which ships its own `roots.pem`), a lancedb native Node addon, bun 1.3.14, node 22.15, deno 2.9.7, uv 0.9.21, Claude Code 2.1.300, Temurin JRE 21.0.12 and `python:3.12-alpine`.

## How it compares

| | trustsweep | grype / trivy / osv-scanner | syft | git-pkgs/certs | emsign-trust-scan |
|---|---|---|---|---|---|
| Says "this bundle still trusts a revoked CA" | ✅ | only for packages with an advisory (certifi, webpki-roots, Go stdlib) | ❌ | ❌ inventory only | ✅ |
| Finds vendored copies (pip `_vendor`, grpcio `roots.pem`) | ✅ | ❌ | ❌ | ✅ | pip only |
| Certificates compiled into binaries (Node, Bun, Deno, Electron) | ✅ | ❌ | ❌ | ✅ | ❌ |
| Bare webpki-roots keys in Rust binaries | ✅ | needs cargo-auditable | ❌ | not seen | ❌ |
| Image layers with whiteouts | ✅ | per package | per package | ❌ | overlay2, needs root |
| Owning package and fixed version | ✅ | ✅ for advisory packages | — | ❌ | partial |
| SARIF output | ✅ | ✅ | ❌ | ❌ | ❌ |

Full table with sources: [docs/comparison.md](docs/comparison.md).

## How it works

- **Extraction by content.** trustsweep reads PEM (including PEM split across C or JS string literals), DER anywhere in a file (which covers JKS, PKCS#12 and compiled-in bundles), escaped byte-string literals (`b"\x30\x82…"`, C octal, `xxd -i` arrays), and the bare public-key bytes of each listed root.
- **Matching.** Certificates match by SHA-256 or by SPKI SHA-256, so a re-issued or cross-signed copy of the same key still matches. OneCRL entries match by SPKI hash, or by issuer and serial.
- **Attribution.** The owning package comes from dist-info `RECORD`, `node_modules/*/package.json`, `pom.properties`, the JDK `release` file, dpkg (including distroless `status.d`), apk, RPM-distro bundle paths, Homebrew Cellar and the cargo registry. Fixed versions come from the incident page's "Who has patched" table.
- **False-positive control.** A file that also contains the revoked intermediates (a chain, a blocklist or an IOC list), or that holds a single certificate, is reported as `REVIEW`, not `TRUSTS`. A file that a later image layer replaces or deletes is reported as `SUPERSEDED`. `--exclude '**/tests/**'` skips paths.

Design notes and incident research are in [docs/design.md](docs/design.md) and [docs/research.md](docs/research.md), both in Chinese.

## Data

The built-in feed has one incident so far: **eMudhra, October 2026**. It holds the 16 revoked intermediate certificates (8 CAs, each with a Sectigo cross-sign), the 4 roots they chain to, and the 1262 enabled Mozilla OneCRL entries. `trustsweep feed update` rebuilds it from [emudhra.we-have-a-problem.com](https://emudhra.we-have-a-problem.com/) and OneCRL and checks every published digest against its PEM. If a source fails, the update stops with an error instead of keeping stale data.

## Limits

- No registry pulls: images come from `docker save`.
- The rpm database is not read, and binary versions are not extracted, so those versions show as unknown.
- No live TLS tests and no auto-fix: trustsweep only reports.

## License

MIT
