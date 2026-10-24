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
trustsweep image python:3.12-alpine                       # pulled straight from the registry, no docker needed
trustsweep image ghcr.io/org/app:tag --platform linux/amd64
trustsweep image ./oci-layout-dir                         # or an OCI layout directory / `docker save` tarball
trustsweep scan . --format sarif -o trustsweep.sarif      # GitHub Code Scanning
trustsweep feed update                                    # rebuild the feed from Mozilla OneCRL, CCADB and incident data
```

Exit code `1` means a live CA bundle still trusts a revoked CA. Exit code `2` means the scan was incomplete or failed. Exit code `0` means neither.

## brotlisweep: embedded Brotli decoders (CVE-2026-111497)

`trustsweep brotlisweep` looks for copies of the Brotli decoder affected by CVE-2026-111497 ("Node2Shell" / "HTTP2Shell") that are bundled inside Mach-O (including each slice of a universal binary), PE and ELF files, Electron frameworks, Bun/Node/Deno single-file programs, and Python Brotli/brotlicffi wheels.

```bash
trustsweep brotlisweep /Applications ~/.bun/bin ~/.local/bin .venv
trustsweep brotlisweep --image node:22 --format sarif -o brotli.sarif
```

Each decoder copy gets one of three results:

- **FIXED**: the string `ERROR_FORMAT_BLOCK_SWITCH`, the error code added by the fix [google/brotli@0ed4268a](https://github.com/google/brotli/commit/0ed4268a4401abcb4472096340477cf4af7d1a2b), is compiled in. This is string evidence, not a code-level proof.
- **UNFIXED**: the marker is missing **and** a version string or package metadata shows a release older than its branch fix (Node 22.23.4 / 24.22.1 / 26.12.1, Bun 1.4.4, PyPI Brotli 1.2.1, brotlicffi 1.2.1.0).
- **UNKNOWN**: the marker is missing and nothing proves the version is old. A missing string alone is never reported as vulnerable.

For a Python Brotli package, it also lists any urllib3, requests, httpx or aiohttp installed next to it. These clients send `Accept-Encoding: br` whenever `brotli` or `brotlicffi` can be imported, which makes the decoder reachable from ordinary HTTP requests.

On Linux and in containers, also run [trailofbits/brotli-checker](https://github.com/trailofbits/brotli-checker). It matches the decoder's compiled code in ELF binaries across 12 architecture targets (x86-64, AArch64, RISC-V64, MIPS and more) and checks source fingerprints, which is much stronger evidence than a string. Its documentation says PE and Mach-O are not classified, and that is the gap brotlisweep covers.

Real run on a Mac ([examples/brotlisweep-macos.txt](examples/brotlisweep-macos.txt)): 25 decoders. 7 were UNFIXED (bun 1.3.14, node 22.15.0, a single-file CLI with embedded Bun 1.4.3, a Node 22.14.0 helper inside a Chromium-based browser, three cached Brotli 1.1.0/1.2.0 wheels), 12 UNKNOWN (five Electron 33–39 apps, Deno 2.9.7, the browser's own framework) and 6 FIXED (five Electron 42+ apps and one Chromium-based framework). App names in the example are replaced with ExampleApp01–14.

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

The scans in [`examples/`](examples/) found affected bundles in certifi 2026.2.25, grpcio 1.78.0 (which ships its own `roots.pem`), a lancedb native Node addon, bun 1.3.14, node 22.15, deno 2.9.7, uv 0.9.21, a Bun-built single-file CLI, Temurin JRE 21.0.12 and `python:3.12-alpine`.

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

The feed is rebuilt in full by `trustsweep feed update` from three public sources. If any of them fails, the update stops with an error instead of keeping stale data.

| Source | What it adds | Result when found in a bundle |
|---|---|---|
| [Mozilla OneCRL](https://firefox.settings.services.mozilla.com/v1/buckets/security-state/collections/onecrl/changeset?_expected=0) | 1262 enabled revoked intermediates (by SPKI hash or issuer + serial) | `REVIEW` |
| [CCADB Mozilla removed-roots report](https://ccadb.my.salesforce-sites.com/mozilla/RemovedCACertificateReportCSVFormat) | 106 unexpired roots Mozilla removed from NSS (expired ones are dropped) | `REVIEW`: the report does not say whether a removal was a distrust or a routine retirement |
| Incident data, currently [eMudhra, October 2026](https://emudhra.we-have-a-problem.com/) | 16 compromised intermediates and the 4 roots that chain to them, with PEM, so bare keys can be found too | `TRUSTS` for the roots |

The numbers are from the built-in snapshot dated 2026-10-24. Fixed versions per package come from a hand-maintained table that `feed update` keeps.

## Limits

- Registry pulls use anonymous tokens, or credentials from `TRUSTSWEEP_REGISTRY_USERNAME`/`_PASSWORD` or the `auths` entries in `~/.docker/config.json`. Docker credential helpers are not run; use `--docker` to scan through the local daemon instead.
- The rpm database is not read, and binary versions are not extracted, so those versions show as unknown.
- No live TLS tests and no auto-fix: trustsweep only reports.

## License

MIT
