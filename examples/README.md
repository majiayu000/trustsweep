# Real scans (2026-10-22 to 2026-10-25)

Home directories are shown as `~`. Each scan ran on a macOS arm64 machine with `target/release/trustsweep`.

| File | Target | Result |
|---|---|---|
| [venv.txt](venv.txt) / [.json](venv.json) / [.sarif](venv.sarif) | a Python 3.11 venv (26,465 files) | TRUSTS: certifi 2026.2.25 → 2026.10.19; grpcio 1.78.0 ships its own `roots.pem` with both affected roots (no fix listed) |
| [node_modules.txt](node_modules.txt) | a 356 MB node_modules (10,978 files) | TRUSTS: `@lancedb/lancedb-darwin-arm64` 0.23.0 native addon embeds the emSign root as a bare key (webpki-roots) |
| [binaries.txt](binaries.txt) | bun 1.3.14, node 22.15.0, deno 2.9.7, uv 0.9.21, a Bun-built single-file CLI (renamed `example-bun-cli`) | all five TRUSTS; uv found only through the embedded-key search |
| [cargo-webpki-roots.txt](cargo-webpki-roots.txt) | webpki-roots 1.0.9 / 1.0.10 and webpki-root-certs 1.0.9 sources | both 1.0.9 crates TRUSTS (webpki-root-certs via escaped byte literals), webpki-roots 1.0.10 clean |
| [jars-gradle-extension.txt](jars-gradle-extension.txt) | 59 jars of a Gradle editor extension (3.17.2) | clean; jar signature blocks are not counted as bundles |
| [temurin-21.0.12-jre.txt](temurin-21.0.12-jre.txt) | `OpenJDK21U-jre_x64_linux_hotspot_21.0.12.1_1.tar.gz` (sha256 `2413149700df…`) from api.adoptium.net | TRUSTS: PKCS#12 `cacerts`, attributed through the `release` file inside the tarball |
| [image-python-3.12-alpine.txt](image-python-3.12-alpine.txt) / [.json](image-python-3.12-alpine.json) | `python:3.12-alpine` @ `sha256:4c47124a8391…` (53 MB) | TRUSTS: apk ca-certificates-bundle 20260909-r0, pip 25.0.1 vendored certifi (also inside the ensurepip wheel); the layer-0 bundle is SUPERSEDED |
| [image-postgres-17-bookworm.txt](image-postgres-17-bookworm.txt) | `postgres:17-bookworm` @ `sha256:639ab7ceb90e…` (459 MB) | clean: the image does not install ca-certificates (checked with `ls /etc/ssl/certs` inside the container) |
| [brotlisweep-macos.txt](brotlisweep-macos.txt) (2026-10-24) | `~/.bun/bin`, node 22.15.0, a Bun-built single-file CLI, deno 2.9.7, three cached Brotli wheels, and `Contents/Frameworks` of 30 apps in `/Applications` (app names replaced with ExampleApp01–14) | 25 decoders: 7 UNFIXED, 12 UNKNOWN, 6 FIXED |
| [brotlisweep-cli.json](brotlisweep-cli.json) / [.sarif](brotlisweep-cli.sarif) | bun, node, the Bun-built CLI, Brotli 1.1.0 wheel | JSON and SARIF forms |
| [registry-alpine-3.20.txt](registry-alpine-3.20.txt) (2026-10-25) | `alpine:3.20` pulled from Docker Hub without docker, linux/arm64 picked from the index | TRUSTS: ca-certificates-bundle 20260413-r0 has emSign ECC Root CA - G3 and 18 roots Mozilla removed |
| [registry-distroless-static-debian12.txt](registry-distroless-static-debian12.txt) / [.json](registry-distroless-static-debian12.json) | `gcr.io/distroless/static-debian12`, `--platform linux/amd64`, 12 layers | TRUSTS: Debian ca-certificates 20250419~deb12u1 (from distroless `status.d`) has AAA Certificate Services, emSign ECC Root CA - G3 and 23 removed roots |
