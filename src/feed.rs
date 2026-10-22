//! Distrust feed: which certificates to look for, and which package versions fix them.

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::extract::{ParsedCert, parse_pem_blocks};

/// Built-in feed, regenerated with `trustsweep feed update --out data/feed.json`.
pub const BUILTIN_FEED: &str = include_str!("../data/feed.json");

pub const INCIDENT_BASE: &str = "https://emudhra.we-have-a-problem.com";
pub const ONECRL_URL: &str = "https://firefox.settings.services.mozilla.com/v1/buckets/security-state/collections/onecrl/changeset?_expected=0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// A root that issued or cross-signed a revoked CA: trusting it means trusting the revoked CA.
    Root,
    /// The revoked CA certificate itself.
    Revoked,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedCert {
    pub name: String,
    pub role: Role,
    pub sha256: String,
    pub spki_sha256: String,
    pub pem: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OneCrlEntry {
    /// base64 DER subject (with `pub_key_hash`) or issuer (with `serial`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pub_key_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fix {
    pub ecosystem: String,
    pub name: String,
    /// Empty means no fixed release yet.
    pub fixed: Vec<String>,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryName {
    pub file: String,
    pub ecosystem: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Feed {
    pub id: String,
    pub generated_at: String,
    pub sources: Vec<String>,
    pub certs: Vec<FeedCert>,
    #[serde(default)]
    pub onecrl: Vec<OneCrlEntry>,
    pub fixes: Vec<Fix>,
    pub binaries: Vec<BinaryName>,
}

/// Where the active feed came from, shown in every report.
#[derive(Debug, Clone, Serialize)]
pub struct FeedInfo {
    pub id: String,
    pub generated_at: String,
    pub origin: String,
    pub certs: usize,
    pub onecrl: usize,
}

/// One thing a found certificate can match.
#[derive(Debug, Clone, Serialize)]
pub struct Target {
    pub name: String,
    pub role: Role,
    pub source: &'static str,
}

/// Feed compiled into lookup tables.
pub struct Matcher {
    pub targets: Vec<Target>,
    by_sha256: HashMap<[u8; 32], usize>,
    by_spki: HashMap<[u8; 32], usize>,
    by_issuer_serial: HashMap<(Vec<u8>, Vec<u8>), usize>,
    /// Raw public-key bytes of feed certificates, for trust anchors embedded without a full certificate.
    pub key_patterns: Vec<(Vec<u8>, usize)>,
    pub fixes: Vec<Fix>,
    pub binaries: Vec<BinaryName>,
    pub info: FeedInfo,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum MatchedBy {
    Sha256,
    Spki,
    IssuerSerial,
    EmbeddedKey,
}

fn hex32(s: &str) -> Result<[u8; 32]> {
    let v = hex::decode(s).with_context(|| format!("bad hex digest {s}"))?;
    v.try_into().map_err(|_| anyhow!("digest {s} is not 32 bytes"))
}

fn b64(s: &str) -> Result<Vec<u8>> {
    B64.decode(s).with_context(|| format!("bad base64 {s}"))
}

impl Feed {
    pub fn parse(text: &str) -> Result<Self> {
        serde_json::from_str(text).context("feed is not valid trustsweep feed JSON")
    }

    pub fn cache_path() -> Option<PathBuf> {
        if let Some(x) = std::env::var_os("XDG_CACHE_HOME") {
            return Some(PathBuf::from(x).join("trustsweep/feed.json"));
        }
        let home = PathBuf::from(std::env::var_os("HOME")?);
        let base = if cfg!(target_os = "macos") {
            home.join("Library/Caches")
        } else {
            home.join(".cache")
        };
        Some(base.join("trustsweep/feed.json"))
    }

    /// Explicit path, else the cache written by `feed update`, else the built-in snapshot.
    pub fn load(explicit: Option<&Path>) -> Result<(Self, String)> {
        let path = match explicit {
            Some(p) => Some(p.to_path_buf()),
            None => Self::cache_path().filter(|p| p.is_file()),
        };
        match path {
            Some(p) => {
                let text = std::fs::read_to_string(&p)
                    .with_context(|| format!("cannot read feed {}", p.display()))?;
                Ok((Self::parse(&text)?, p.display().to_string()))
            }
            None => Ok((Self::parse(BUILTIN_FEED)?, "builtin".to_string())),
        }
    }

    pub fn compile(&self, origin: String) -> Result<Matcher> {
        let mut m = Matcher {
            targets: Vec::new(),
            by_sha256: HashMap::new(),
            by_spki: HashMap::new(),
            by_issuer_serial: HashMap::new(),
            key_patterns: Vec::new(),
            fixes: self.fixes.clone(),
            binaries: self.binaries.clone(),
            info: FeedInfo {
                id: self.id.clone(),
                generated_at: self.generated_at.clone(),
                origin,
                certs: self.certs.len(),
                onecrl: self.onecrl.len(),
            },
        };
        for c in &self.certs {
            let idx = m.targets.len();
            m.targets.push(Target {
                name: c.name.clone(),
                role: c.role,
                source: "feed",
            });
            m.by_sha256.insert(hex32(&c.sha256)?, idx);
            // Cross-signs share a key: the first role seen for a key wins, roots are listed first.
            m.by_spki.entry(hex32(&c.spki_sha256)?).or_insert(idx);
            let parsed = parse_pem_blocks(c.pem.as_bytes());
            let cert = parsed
                .first()
                .ok_or_else(|| anyhow!("feed cert {} has no parsable PEM", c.name))?;
            if !cert.sha256.eq_ignore_ascii_case(&c.sha256) {
                bail!("feed cert {}: PEM does not match sha256", c.name);
            }
            if !m.key_patterns.iter().any(|(k, _)| *k == cert.public_key) {
                m.key_patterns.push((cert.public_key.clone(), idx));
            }
        }
        for e in &self.onecrl {
            let idx = m.targets.len();
            match (&e.subject, &e.pub_key_hash, &e.issuer, &e.serial) {
                (Some(subject), Some(hash), _, _) => {
                    let key: [u8; 32] = b64(hash)?
                        .try_into()
                        .map_err(|_| anyhow!("OneCRL pubKeyHash {hash} is not 32 bytes"))?;
                    if m.by_spki.contains_key(&key) {
                        continue;
                    }
                    m.targets.push(Target {
                        name: name_cn(&b64(subject)?),
                        role: Role::Revoked,
                        source: "onecrl",
                    });
                    m.by_spki.insert(key, idx);
                }
                (_, _, Some(issuer), Some(serial)) => {
                    let issuer = b64(issuer)?;
                    m.targets.push(Target {
                        name: format!("serial {} issued by {}", hex::encode(b64(serial)?), name_cn(&issuer)),
                        role: Role::Revoked,
                        source: "onecrl",
                    });
                    m.by_issuer_serial.insert((issuer, b64(serial)?), idx);
                }
                _ => bail!("OneCRL entry has neither subject+pub_key_hash nor issuer+serial"),
            }
        }
        Ok(m)
    }
}

/// Common name of a DER-encoded X.509 Name, or the whole name as text.
pub fn name_cn(der: &[u8]) -> String {
    use x509_parser::prelude::FromDer;
    match x509_parser::x509::X509Name::from_der(der) {
        Ok((_, name)) => name
            .iter_common_name()
            .next()
            .and_then(|cn| cn.as_str().ok().map(str::to_string))
            .unwrap_or_else(|| name.to_string()),
        Err(_) => format!("<unparsable name {}>", hex::encode(der)),
    }
}

impl Matcher {
    pub fn match_cert(&self, c: &ParsedCert) -> Option<(usize, MatchedBy)> {
        if let Some(&i) = self.by_sha256.get(&c.sha256_bytes) {
            return Some((i, MatchedBy::Sha256));
        }
        if let Some(&i) = self.by_spki.get(&c.spki_sha256_bytes) {
            return Some((i, MatchedBy::Spki));
        }
        self.by_issuer_serial
            .get(&(c.issuer_der.clone(), c.serial.clone()))
            .map(|&i| (i, MatchedBy::IssuerSerial))
    }

    pub fn fix_for(&self, ecosystem: &str, name: &str) -> Option<&Fix> {
        let norm = |s: &str| s.to_ascii_lowercase().replace('_', "-");
        self.fixes
            .iter()
            .find(|f| f.ecosystem == ecosystem && norm(&f.name) == norm(name))
    }
}

fn fetch(url: &str) -> Result<String> {
    ureq::get(url)
        .call()
        .with_context(|| format!("GET {url}"))?
        .body_mut()
        .with_config()
        .limit(64 * 1024 * 1024)
        .read_to_string()
        .with_context(|| format!("reading body of {url}"))
}

#[derive(Deserialize)]
struct IncidentCert {
    name: String,
    sha256: String,
    spki_sha256: String,
    pem: String,
}

#[derive(Deserialize)]
struct OneCrlChangeset {
    changes: Vec<OneCrlRecord>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OneCrlRecord {
    subject: Option<String>,
    pub_key_hash: Option<String>,
    issuer_name: Option<String>,
    serial_number: Option<String>,
    #[serde(default = "enabled_default")]
    enabled: bool,
}

fn enabled_default() -> bool {
    true
}

/// Rebuild certs and OneCRL entries from the live sources, keeping the hand-maintained fix table.
pub fn update(base: &Feed, incident_base: &str, onecrl_url: &str, now: String) -> Result<Feed> {
    let roots_url = format!("{incident_base}/roots.json");
    let inter_url = format!("{incident_base}/impacted-intermediates.json");
    let roots: Vec<IncidentCert> =
        serde_json::from_str(&fetch(&roots_url)?).with_context(|| format!("parsing {roots_url}"))?;
    let inters: Vec<IncidentCert> =
        serde_json::from_str(&fetch(&inter_url)?).with_context(|| format!("parsing {inter_url}"))?;
    let onecrl: OneCrlChangeset =
        serde_json::from_str(&fetch(onecrl_url)?).with_context(|| format!("parsing {onecrl_url}"))?;
    if roots.is_empty() || inters.is_empty() || onecrl.changes.is_empty() {
        bail!("a feed source returned an empty list; refusing to write a feed without it");
    }

    let mut certs = Vec::new();
    for (role, list) in [(Role::Root, roots), (Role::Revoked, inters)] {
        for c in list {
            let parsed = parse_pem_blocks(c.pem.as_bytes());
            let p = parsed
                .first()
                .ok_or_else(|| anyhow!("{}: PEM does not parse", c.name))?;
            if !p.sha256.eq_ignore_ascii_case(&c.sha256) || !p.spki_sha256.eq_ignore_ascii_case(&c.spki_sha256) {
                bail!("{}: published digests do not match its PEM", c.name);
            }
            certs.push(FeedCert {
                name: c.name,
                role,
                sha256: p.sha256.clone(),
                spki_sha256: p.spki_sha256.clone(),
                pem: c.pem,
            });
        }
    }

    let onecrl = onecrl
        .changes
        .into_iter()
        .filter(|r| r.enabled)
        .map(|r| OneCrlEntry {
            subject: r.subject.filter(|_| r.pub_key_hash.is_some()),
            pub_key_hash: r.pub_key_hash,
            issuer: r.issuer_name,
            serial: r.serial_number,
        })
        .collect();

    Ok(Feed {
        id: base.id.clone(),
        generated_at: now,
        sources: vec![roots_url, inter_url, onecrl_url.to_string()],
        certs,
        onecrl,
        fixes: base.fixes.clone(),
        binaries: base.binaries.clone(),
    })
}
