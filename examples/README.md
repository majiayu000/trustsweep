# Real scans (2026-10-22, feed `emudhra-2026-10` built in)

Home directories are shown as `~`. Each scan ran on a macOS arm64 machine with `target/release/trustsweep`.

| File | Target | Result |
|---|---|---|
| [venv.txt](venv.txt) / [.json](venv.json) / [.sarif](venv.sarif) | a Python 3.11 venv (26,465 files) | TRUSTS: certifi 2026.2.25 → 2026.10.19; grpcio 1.78.0 ships its own `roots.pem` with both affected roots (no fix listed) |
| [node_modules.txt](node_modules.txt) | a 356 MB node_modules (10,978 files) | TRUSTS: `@lancedb/lancedb-darwin-arm64` 0.23.0 native addon embeds the emSign root as a bare key (webpki-roots) |
| [binaries.txt](binaries.txt) | bun 1.3.14, node 22.15.0, deno 2.9.7, uv 0.9.21, Claude Code 2.1.300 | all five TRUSTS; uv found only through the embedded-key search |
| [cargo-webpki-roots.txt](cargo-webpki-roots.txt) | webpki-roots 1.0.9 and 1.0.10 sources | 1.0.9 TRUSTS, 1.0.10 clean |
| [jars-gradle-extension.txt](jars-gradle-extension.txt) | 59 jars of the VS Code Gradle extension 3.17.2 | clean; jar signature blocks are not counted as bundles |
| [temurin-21.0.12-jre.txt](temurin-21.0.12-jre.txt) | `OpenJDK21U-jre_x64_linux_hotspot_21.0.12.1_1.tar.gz` (sha256 `2413149700df…`) from api.adoptium.net | TRUSTS: PKCS#12 `cacerts`, attributed through the `release` file inside the tarball |
| [image-python-3.12-alpine.txt](image-python-3.12-alpine.txt) / [.json](image-python-3.12-alpine.json) | `python:3.12-alpine` @ `sha256:4c47124a8391…` (53 MB) | TRUSTS: apk ca-certificates-bundle 20260909-r0, pip 25.0.1 vendored certifi (also inside the ensurepip wheel); the layer-0 bundle is SUPERSEDED |
| [image-postgres-17-bookworm.txt](image-postgres-17-bookworm.txt) | `postgres:17-bookworm` @ `sha256:639ab7ceb90e…` (459 MB) | clean: the image does not install ca-certificates (checked with `ls /etc/ssl/certs` inside the container) |
