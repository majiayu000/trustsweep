# trustsweep

Find the CA bundles your artifacts carry with them (venvs, node_modules, wheels, jars, container image layers, single-file binaries) that still trust a revoked CA, and see which package to upgrade.

Updating the OS trust store does not reach the copies that pip, Node, Bun, Deno, uv, Java and many SDKs ship themselves. The first feed covers the [October 2026 eMudhra intermediate CA compromise](https://emudhra.we-have-a-problem.com/): 8 compromised intermediates, 16 certificates including the Sectigo cross-signs, the 4 roots they chain to, and Mozilla OneCRL.

## Install

```bash
cargo install --git <repo-url> trustsweep
```

Or build from a checkout:

```bash
cargo build --release
```

## Usage

```bash
trustsweep scan .venv node_modules ~/.local/bin/uv app.jar
trustsweep image python:3.12-alpine          # runs `docker save`, or pass a saved .tar
trustsweep scan . --format sarif -o trustsweep.sarif
trustsweep feed update                        # refresh from the incident JSON + OneCRL
```

Exit codes: `1` when a live trust store still trusts a revoked CA, `2` when the scan was incomplete (unreadable files, oversized entries), `0` otherwise.

## Example output

`trustsweep image python:3.12-alpine` (image digest `sha256:4c47124a…`, scanned 2026-10-22):

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

A Rust binary built with webpki-roots has no certificates in it, only the root keys. trustsweep finds those too:

```
TRUSTS     ~/.local/bin/uv
           embeds the public key of a root that issued or cross-signed a revoked CA, the way webpki-roots stores trust anchors (removed in webpki-roots 1.0.10); rebuild against the fixed version (0 certs in file)
           - emSign ECC Root CA - G3 [root, feed, matched by embedded-key at byte 35634726]
           package: generic uv version unknown  (from executable named uv)
           fix: upgrade to 0.13.4 (https://github.com/astral-sh/uv/releases/tag/0.13.4)
```

More real scans are in [`examples/`](examples/): a Python venv, node_modules, a set of jars, local binaries, cargo sources, and two public images.

## How it works

- Certificates are found by content, not file name: PEM (including PEM split across C or JS string literals), DER anywhere in a file (which covers JKS, PKCS#12 and compiled-in bundles), and the bare public-key bytes of each listed root.
- Each certificate is matched by SHA-256 or SPKI SHA-256, so a re-issued or cross-signed copy of the same key still matches. OneCRL entries are matched by SPKI hash or by issuer and serial.
- Owners come from dist-info `RECORD`, `node_modules/*/package.json`, `pom.properties`, the JDK `release` file, dpkg and apk databases, Homebrew Cellar paths and cargo registry paths. The suggested fixed versions come from the incident page's "Who has patched" table.
- In images, a file that a later layer overwrites or whites out is reported as `SUPERSEDED` and does not fail the scan.
- A file that also contains the revoked intermediates (a chain, a blocklist or an IOC list), or that holds a single certificate, is reported as `REVIEW`, not `TRUSTS`.

See [docs/design.md](docs/design.md) and [docs/research.md](docs/research.md) (both in Chinese).

## Limits

trustsweep does not pull images from a registry or read the rpm database. It does not parse Go buildinfo, and it does not compare versions: a finding is based on the certificate actually being present. Binaries are attributed only by file name, so their version is reported as unknown. webpki-root-certs embedded as escaped Rust byte strings in source form is not detected; compiled binaries are.

## License

Not chosen yet.
