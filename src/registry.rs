//! Pull image manifests and layers from an OCI registry or an OCI image layout directory,
//! verify every blob against its digest, and hand the layers to the scanner in order.

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::scan::Scanner;

const MANIFEST_ACCEPT: &str = "application/vnd.oci.image.index.v1+json, \
application/vnd.oci.image.manifest.v1+json, \
application/vnd.docker.distribution.manifest.list.v2+json, \
application/vnd.docker.distribution.manifest.v2+json";
const MAX_MANIFEST_BYTES: u64 = 8 * 1024 * 1024;
const DOCKER_HUB: &str = "registry-1.docker.io";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageRef {
    pub registry: String,
    pub repository: String,
    /// Tag or `sha256:` digest.
    pub reference: String,
}

/// `alpine`, `alpine:3.20`, `ghcr.io/o/r:tag`, `localhost:5000/r@sha256:…`.
pub fn parse_ref(s: &str) -> Result<ImageRef> {
    let (name, reference) = match s.split_once('@') {
        Some((n, d)) => (n, d.to_string()),
        None => match s.rsplit_once(':') {
            Some((n, t)) if !t.contains('/') => (n, t.to_string()),
            _ => (s, "latest".to_string()),
        },
    };
    let (registry, repository) = match name.split_once('/') {
        Some((first, rest)) if first.contains('.') || first.contains(':') || first == "localhost" => {
            (first.to_string(), rest.to_string())
        }
        _ => (DOCKER_HUB.to_string(), name.to_string()),
    };
    let registry = if registry == "docker.io" || registry == "index.docker.io" {
        DOCKER_HUB.to_string()
    } else {
        registry
    };
    let repository = if registry == DOCKER_HUB && !repository.contains('/') {
        format!("library/{repository}")
    } else {
        repository
    };
    if repository.is_empty() || reference.is_empty() {
        bail!("cannot parse image reference {s}");
    }
    Ok(ImageRef { registry, repository, reference })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Platform {
    pub os: String,
    pub arch: String,
    pub variant: Option<String>,
}

impl Platform {
    /// `linux/amd64` or `linux/arm64/v8`.
    pub fn parse(s: &str) -> Result<Self> {
        let mut it = s.split('/');
        let (Some(os), Some(arch)) = (it.next(), it.next()) else {
            bail!("platform must look like os/arch[/variant], got {s}");
        };
        Ok(Self {
            os: os.into(),
            arch: arch.into(),
            variant: it.next().map(str::to_string),
        })
    }

    /// Linux on this machine's CPU, using OCI architecture names.
    pub fn host() -> Self {
        let arch = match std::env::consts::ARCH {
            "x86_64" => "amd64",
            "aarch64" => "arm64",
            "x86" => "386",
            "powerpc64" => "ppc64le",
            other => other,
        };
        Self {
            os: "linux".into(),
            arch: arch.into(),
            variant: None,
        }
    }

    fn matches(&self, p: &Value) -> bool {
        let field = |k: &str| p.get(k).and_then(Value::as_str);
        field("os") == Some(self.os.as_str())
            && field("architecture") == Some(self.arch.as_str())
            && self.variant.as_deref().is_none_or(|v| field("variant") == Some(v))
    }
}

impl std::fmt::Display for Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.os, self.arch)?;
        if let Some(v) = &self.variant {
            write!(f, "/{v}")?;
        }
        Ok(())
    }
}

/// Where manifests and blobs come from.
pub trait Source {
    /// Manifest or index bytes for a tag or digest.
    fn manifest(&mut self, reference: &str) -> Result<Vec<u8>>;
    /// Stream a blob into `out`.
    fn blob(&mut self, digest: &str, out: &mut File) -> Result<()>;
    fn describe(&self) -> String;
}

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

fn check_digest(digest: &str, actual_hex: &str) -> Result<()> {
    let want = digest
        .strip_prefix("sha256:")
        .ok_or_else(|| anyhow!("unsupported digest algorithm in {digest}"))?;
    if want != actual_hex {
        bail!("digest mismatch: expected {digest}, got sha256:{actual_hex}");
    }
    Ok(())
}

/// What was scanned, for the report header.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Pulled {
    pub source: String,
    pub manifest_digest: String,
    pub platform: Option<String>,
    pub layers: usize,
}

/// Resolve `reference` to a single-platform manifest and scan its layers in order.
pub fn pull_and_scan(src: &mut dyn Source, reference: &str, platform: &Platform, scanner: &mut Scanner) -> Result<Pulled> {
    let mut bytes = src.manifest(reference)?;
    if reference.starts_with("sha256:") {
        check_digest(reference, &sha256_hex(&bytes))?;
    }
    let mut doc: Value = serde_json::from_slice(&bytes).context("manifest is not JSON")?;
    let mut chosen = None;
    if let Some(list) = doc.get("manifests").and_then(Value::as_array) {
        let pick = list
            .iter()
            .find(|m| m.get("platform").is_some_and(|p| platform.matches(p)))
            .or_else(|| (list.len() == 1 && list[0].get("platform").is_none()).then(|| &list[0]))
            .ok_or_else(|| {
                let have: Vec<String> = list
                    .iter()
                    .filter_map(|m| m.get("platform"))
                    .map(|p| {
                        let f = |k: &str| p.get(k).and_then(Value::as_str).unwrap_or("");
                        [f("os"), f("architecture"), f("variant")].iter().filter(|x| !x.is_empty()).copied().collect::<Vec<_>>().join("/")
                    })
                    .collect();
                anyhow!("no manifest for platform {platform}; the index has: {}", have.join(", "))
            })?;
        let digest = pick
            .get("digest")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("index entry without digest"))?
            .to_string();
        bytes = src.manifest(&digest)?;
        check_digest(&digest, &sha256_hex(&bytes))?;
        doc = serde_json::from_slice(&bytes).context("platform manifest is not JSON")?;
        chosen = Some(platform.to_string());
    }
    let manifest_digest = format!("sha256:{}", sha256_hex(&bytes));
    let layers = doc
        .get("layers")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("manifest has no layers (schema 1 manifests are not supported)"))?;

    let tmp = tempfile::tempdir().context("creating a temporary directory for layer blobs")?;
    for (i, layer) in layers.iter().enumerate() {
        let digest = layer
            .get("digest")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("layer {i} has no digest"))?;
        if layer.get("urls").is_some() {
            bail!("layer {digest} is a foreign layer hosted elsewhere; it is not downloaded");
        }
        let path = tmp.path().join(format!("layer-{i}"));
        let mut file = File::options().create_new(true).read(true).write(true).open(&path)?;
        src.blob(digest, &mut file).with_context(|| format!("fetching layer {digest}"))?;
        file.seek(SeekFrom::Start(0))?;
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; 1 << 20];
        loop {
            let n = std::io::Read::read(&mut file, &mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        check_digest(digest, &hex::encode(hasher.finalize()))?;
        file.seek(SeekFrom::Start(0))?;
        scanner.scan_layer_blob(&mut file, digest)?;
        drop(file);
        std::fs::remove_file(&path)?;
    }
    scanner.finish_layers();
    Ok(Pulled {
        source: src.describe(),
        manifest_digest,
        platform: chosen,
        layers: layers.len(),
    })
}

/// An OCI image layout directory (`oci-layout`, `index.json`, `blobs/sha256/…`).
pub struct OciLayout {
    pub dir: PathBuf,
}

impl OciLayout {
    pub fn is_layout(dir: &Path) -> bool {
        dir.join("oci-layout").is_file() && dir.join("index.json").is_file()
    }

    fn blob_path(&self, digest: &str) -> Result<PathBuf> {
        let hex = digest
            .strip_prefix("sha256:")
            .filter(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()))
            .ok_or_else(|| anyhow!("bad digest {digest}"))?;
        Ok(self.dir.join("blobs/sha256").join(hex))
    }
}

impl Source for OciLayout {
    fn manifest(&mut self, reference: &str) -> Result<Vec<u8>> {
        if reference.starts_with("sha256:") {
            return std::fs::read(self.blob_path(reference)?).with_context(|| format!("reading blob {reference}"));
        }
        // The layout's index.json is itself an index; a tag selects by ref-name annotation.
        let index = std::fs::read(self.dir.join("index.json")).context("reading index.json")?;
        if reference.is_empty() {
            return Ok(index);
        }
        let doc: Value = serde_json::from_slice(&index).context("index.json is not JSON")?;
        let entry = doc
            .get("manifests")
            .and_then(Value::as_array)
            .and_then(|l| {
                l.iter().find(|m| {
                    m.pointer("/annotations/org.opencontainers.image.ref.name").and_then(Value::as_str) == Some(reference)
                })
            })
            .ok_or_else(|| anyhow!("no manifest tagged {reference} in {}", self.dir.display()))?;
        let digest = entry.get("digest").and_then(Value::as_str).ok_or_else(|| anyhow!("index entry without digest"))?;
        std::fs::read(self.blob_path(digest)?).with_context(|| format!("reading blob {digest}"))
    }

    fn blob(&mut self, digest: &str, out: &mut File) -> Result<()> {
        let mut f = File::open(self.blob_path(digest)?).with_context(|| format!("opening blob {digest}"))?;
        std::io::copy(&mut f, out)?;
        Ok(())
    }

    fn describe(&self) -> String {
        format!("OCI layout {}", self.dir.display())
    }
}

/// A registry speaking the OCI Distribution API over HTTPS.
pub struct Registry {
    image: ImageRef,
    agent: ureq::Agent,
    auth: Option<String>,
    basic: Option<(String, String)>,
}

/// Credentials from `TRUSTSWEEP_REGISTRY_USERNAME`/`_PASSWORD`, else the `auths` entry in the
/// docker config (`$DOCKER_CONFIG/config.json` or `~/.docker/config.json`). Credential helpers
/// are not executed.
pub fn credentials(registry: &str) -> Result<Option<(String, String)>> {
    if let (Ok(u), Ok(p)) = (std::env::var("TRUSTSWEEP_REGISTRY_USERNAME"), std::env::var("TRUSTSWEEP_REGISTRY_PASSWORD")) {
        return Ok(Some((u, p)));
    }
    let path = match std::env::var_os("DOCKER_CONFIG") {
        Some(d) => PathBuf::from(d).join("config.json"),
        None => match std::env::var_os("HOME") {
            Some(h) => PathBuf::from(h).join(".docker/config.json"),
            None => return Ok(None),
        },
    };
    let Ok(text) = std::fs::read_to_string(&path) else {
        return Ok(None);
    };
    credentials_from_config(&text, registry).with_context(|| format!("reading credentials from {}", path.display()))
}

/// The `auths.<registry>.auth` entry of a docker config.json, decoded to user and password.
pub fn credentials_from_config(text: &str, registry: &str) -> Result<Option<(String, String)>> {
    let cfg: Value = serde_json::from_str(text).context("config is not JSON")?;
    let keys: Vec<String> = if registry == DOCKER_HUB {
        vec!["https://index.docker.io/v1/".into(), "index.docker.io".into(), "docker.io".into()]
    } else {
        vec![registry.to_string(), format!("https://{registry}")]
    };
    let auths = cfg.get("auths").and_then(Value::as_object);
    for k in keys {
        if let Some(auth) = auths.and_then(|a| a.get(&k)).and_then(|a| a.get("auth")).and_then(Value::as_str) {
            let decoded = String::from_utf8(B64.decode(auth).with_context(|| format!("bad auth for {k}"))?)?;
            if let Some((u, p)) = decoded.split_once(':') {
                return Ok(Some((u.to_string(), p.to_string())));
            }
        }
    }
    Ok(None)
}

/// Parse `Bearer realm="…",service="…",scope="…"`.
pub fn parse_challenge(header: &str) -> Option<(String, Vec<(String, String)>)> {
    let (scheme, rest) = header.trim().split_once(' ')?;
    let mut params = Vec::new();
    let mut rest = rest.trim();
    while !rest.is_empty() {
        let (key, after) = rest.split_once('=')?;
        let after = after.trim_start();
        let (value, tail) = if let Some(q) = after.strip_prefix('"') {
            let end = q.find('"')?;
            (&q[..end], &q[end + 1..])
        } else {
            after.split_once(',').unwrap_or((after, ""))
        };
        params.push((key.trim().to_ascii_lowercase(), value.to_string()));
        rest = tail.trim_start_matches(',').trim();
    }
    Some((scheme.to_ascii_lowercase(), params))
}

impl Registry {
    pub fn new(image: ImageRef) -> Result<Self> {
        let basic = credentials(&image.registry)?;
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .timeout_global(Some(std::time::Duration::from_secs(600)))
            .build()
            .into();
        Ok(Self {
            image,
            agent,
            auth: None,
            basic,
        })
    }

    fn basic_header(&self) -> Option<String> {
        self.basic.as_ref().map(|(u, p)| format!("Basic {}", B64.encode(format!("{u}:{p}"))))
    }

    /// Answer a 401 challenge: a bearer token from the realm (anonymous unless credentials exist), or basic auth.
    fn authenticate(&mut self, challenge: &str) -> Result<()> {
        let (scheme, params) = parse_challenge(challenge).ok_or_else(|| anyhow!("unparsable WWW-Authenticate: {challenge}"))?;
        if scheme == "basic" {
            self.auth = Some(self.basic_header().ok_or_else(|| anyhow!("{} requires credentials", self.image.registry))?);
            return Ok(());
        }
        let get = |k: &str| params.iter().find(|(key, _)| key == k).map(|(_, v)| v.as_str());
        let realm = get("realm").ok_or_else(|| anyhow!("bearer challenge without realm"))?;
        let mut req = self.agent.get(realm).query("service", get("service").unwrap_or_default());
        let scope = get("scope").map(str::to_string).unwrap_or_else(|| format!("repository:{}:pull", self.image.repository));
        req = req.query("scope", &scope);
        if let Some(b) = self.basic_header() {
            req = req.header("Authorization", &b);
        }
        let mut resp = req.call().with_context(|| format!("token request to {realm}"))?;
        if !resp.status().is_success() {
            bail!("token request to {realm} failed with {}", resp.status());
        }
        let body: Value = serde_json::from_slice(&resp.body_mut().with_config().limit(MAX_MANIFEST_BYTES).read_to_vec()?)?;
        let token = body
            .get("token")
            .or_else(|| body.get("access_token"))
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("token response from {realm} has no token"))?;
        self.auth = Some(format!("Bearer {token}"));
        Ok(())
    }

    fn get(&mut self, path: &str, accept: &str) -> Result<ureq::http::Response<ureq::Body>> {
        let url = format!("https://{}/v2/{}/{path}", self.image.registry, self.image.repository);
        for attempt in 0..2 {
            let mut req = self.agent.get(&url).header("Accept", accept);
            if let Some(a) = &self.auth {
                req = req.header("Authorization", a);
            }
            let resp = req.call().with_context(|| format!("GET {url}"))?;
            let status = resp.status();
            if status == 401 && attempt == 0 {
                let challenge = resp
                    .headers()
                    .get("www-authenticate")
                    .and_then(|v| v.to_str().ok())
                    .ok_or_else(|| anyhow!("401 from {url} without WWW-Authenticate"))?
                    .to_string();
                self.authenticate(&challenge)?;
                continue;
            }
            if !status.is_success() {
                let hint = if status == 401 || status == 403 {
                    " (private image? set TRUSTSWEEP_REGISTRY_USERNAME/_PASSWORD or log in with `docker login`; credential helpers are not used)"
                } else {
                    ""
                };
                bail!("GET {url} returned {status}{hint}");
            }
            return Ok(resp);
        }
        bail!("GET {url}: authentication failed")
    }
}

impl Source for Registry {
    fn manifest(&mut self, reference: &str) -> Result<Vec<u8>> {
        let mut resp = self.get(&format!("manifests/{reference}"), MANIFEST_ACCEPT)?;
        Ok(resp.body_mut().with_config().limit(MAX_MANIFEST_BYTES).read_to_vec()?)
    }

    fn blob(&mut self, digest: &str, out: &mut File) -> Result<()> {
        let resp = self.get(&format!("blobs/{digest}"), "*/*")?;
        let mut reader = resp.into_body().into_with_config().limit(u64::MAX).reader();
        std::io::copy(&mut reader, out)?;
        out.flush()?;
        Ok(())
    }

    fn describe(&self) -> String {
        format!("{}/{}:{}", self.image.registry, self.image.repository, self.image.reference)
    }
}
