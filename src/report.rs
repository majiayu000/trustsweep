//! Turn scan hits into verdicts and render them as text, JSON or SARIF.

use serde::Serialize;
use serde_json::json;
use std::fmt::Write;

use crate::attribute::{Owner, attribute};
use crate::extract::Encoding;
use crate::feed::{FeedInfo, Fix, MatchedBy, Role};
use crate::registry::Pulled;
use crate::scan::{Bundle, ScanError, Scanner, Stats};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    /// The file is a trust store that still accepts certificates from a revoked CA.
    Trusts,
    /// A listed certificate is present but the file does not look like a trust store.
    Review,
}

#[derive(Debug, Clone, Serialize)]
pub struct MatchOut {
    pub name: String,
    pub role: Role,
    pub source: &'static str,
    pub matched_by: MatchedBy,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encoding: Option<Encoding>,
    pub offset: usize,
    pub len: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub layer: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub layer_digest: Option<String>,
    pub verdict: Verdict,
    pub reason: String,
    pub superseded: bool,
    pub cert_count: usize,
    pub matches: Vec<MatchOut>,
    pub owner: Option<Owner>,
    pub fix: Option<Fix>,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub tool: &'static str,
    pub version: &'static str,
    pub feed: FeedInfo,
    pub stats: Stats,
    pub findings: Vec<Finding>,
    pub bundles: Vec<Bundle>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub layers: Vec<String>,
    pub errors: Vec<ScanError>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<Pulled>,
}

impl Report {
    pub fn build(scanner: Scanner) -> Self {
        let m = scanner.matcher;
        let findings = scanner
            .hit_files
            .iter()
            .map(|f| {
                let matches: Vec<MatchOut> = f
                    .hits
                    .iter()
                    .map(|h| {
                        let t = &m.targets[h.target];
                        MatchOut {
                            name: t.name.clone(),
                            role: t.role,
                            source: t.source,
                            matched_by: h.matched_by,
                            encoding: h.encoding,
                            offset: h.offset,
                            len: h.len,
                            cert_sha256: h.cert_sha256.clone(),
                        }
                    })
                    .collect();
                let has_root = matches.iter().any(|x| x.role == Role::Root);
                let has_revoked = matches.iter().any(|x| x.role == Role::Revoked);
                let embedded = matches.iter().any(|x| x.matched_by == MatchedBy::EmbeddedKey);
                let (verdict, reason) = if has_root && has_revoked {
                    (Verdict::Review, "also contains revoked CA certificates: looks like a chain, blocklist or IOC file, not a trust store")
                } else if has_root && f.cert_count <= 1 && !embedded {
                    (Verdict::Review, "single certificate, not a bundle: may be a test fixture or a pinned anchor")
                } else if has_root && f.cert_count == 0 {
                    (Verdict::Trusts, "embeds the public key of a root that issued or cross-signed a revoked CA, the way webpki-roots stores trust anchors (removed in webpki-roots 1.0.10); rebuild against the fixed version")
                } else if has_root {
                    (Verdict::Trusts, "trust store contains a root that issued or cross-signed a revoked CA")
                } else if has_revoked {
                    (Verdict::Review, "contains a revoked CA certificate: check whether it is used as a trust anchor")
                } else {
                    (Verdict::Review, "still contains roots Mozilla has removed from its root store: the bundle predates that NSS release or follows another root program")
                };
                let owner = attribute(&f.path, &scanner.store, &m.binaries);
                let fix = owner.as_ref().and_then(|o| m.fix_for(&o.ecosystem, &o.name)).cloned();
                Finding {
                    path: f.path.clone(),
                    layer: f.layer,
                    layer_digest: f.layer.and_then(|l| scanner.layers.get(l).cloned()),
                    verdict,
                    reason: reason.to_string(),
                    superseded: f.superseded,
                    cert_count: f.cert_count,
                    matches,
                    owner,
                    fix,
                }
            })
            .collect();
        Report {
            tool: "trustsweep",
            version: env!("CARGO_PKG_VERSION"),
            feed: m.info.clone(),
            stats: scanner.stats,
            findings,
            bundles: scanner.bundles,
            layers: scanner.layers,
            errors: scanner.errors,
            image: scanner.image,
        }
    }

    pub fn failing(&self) -> usize {
        self.findings
            .iter()
            .filter(|f| f.verdict == Verdict::Trusts && !f.superseded)
            .count()
    }

    /// 1 when a live trust store trusts a revoked CA, 2 when coverage is incomplete, else 0.
    pub fn exit_code(&self) -> i32 {
        if self.failing() > 0 {
            1
        } else if !self.errors.is_empty() {
            2
        } else {
            0
        }
    }

    pub fn text(&self, verbose: bool) -> String {
        let mut s = String::new();
        let f = &self.feed;
        let _ = writeln!(
            s,
            "trustsweep {} | feed {} ({}, generated {}, {} incident certs, {} OneCRL entries, {} removed roots)",
            self.version, f.id, f.origin, f.generated_at, f.certs, f.onecrl, f.removed
        );
        if let Some(i) = &self.image {
            let _ = writeln!(s, "image {} | manifest {} | {} | {} layers", i.source, i.manifest_digest, i.platform.as_deref().unwrap_or("single-platform"), i.layers);
        }
        let live_bundles = self.bundles.iter().filter(|b| !b.superseded).count();
        let _ = writeln!(
            s,
            "scanned {} files, {} archives, {} excluded | {} CA bundles found | {} errors\n",
            self.stats.files, self.stats.archives, self.stats.excluded, live_bundles, self.errors.len()
        );
        let mut sorted: Vec<&Finding> = self.findings.iter().collect();
        sorted.sort_by_key(|x| (x.superseded, x.verdict != Verdict::Trusts, x.path.clone()));
        for x in sorted {
            let tag = match (x.verdict, x.superseded) {
                (_, true) => "SUPERSEDED",
                (Verdict::Trusts, _) => "TRUSTS",
                (Verdict::Review, _) => "REVIEW",
            };
            let _ = writeln!(s, "{tag:<10} {}", x.path);
            if let (Some(l), Some(d)) = (x.layer, &x.layer_digest) {
                let short = d.get(..19).unwrap_or(d);
                let _ = writeln!(s, "           layer {l} ({short})");
            }
            let _ = writeln!(s, "           {} ({} certs in file)", x.reason, x.cert_count);
            let removed: Vec<&str> = x
                .matches
                .iter()
                .filter(|mo| mo.role == Role::Removed)
                .map(|mo| mo.name.as_str())
                .collect();
            if !removed.is_empty() {
                let _ = writeln!(s, "           - {} roots Mozilla removed: {}", removed.len(), removed.join("; "));
            }
            for mo in x.matches.iter().filter(|mo| mo.role != Role::Removed) {
                let role = match mo.role {
                    Role::Root => "root",
                    Role::Revoked => "revoked",
                    Role::Removed => "removed",
                };
                let by = serde_json::to_value(mo.matched_by).ok().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default();
                let _ = writeln!(s, "           - {} [{role}, {}, matched by {by} at byte {}]", mo.name, mo.source, mo.offset);
            }
            match &x.owner {
                Some(o) => {
                    let v = o.version.as_deref().unwrap_or("version unknown");
                    let _ = writeln!(s, "           package: {} {} {v}  (from {})", o.ecosystem, o.name, o.evidence);
                }
                None => {
                    let _ = writeln!(s, "           package: unknown");
                }
            }
            match &x.fix {
                Some(fix) if fix.fixed.is_empty() => {
                    let _ = writeln!(s, "           fix: no fixed release yet ({})", fix.source);
                }
                Some(fix) => {
                    let _ = writeln!(s, "           fix: upgrade to {} ({})", fix.fixed.join(" / "), fix.source);
                }
                None => {}
            }
            s.push('\n');
        }
        if self.findings.is_empty() {
            s.push_str("no listed certificates found\n\n");
        }
        if verbose {
            for b in self.bundles.iter().filter(|b| !b.superseded) {
                let _ = writeln!(s, "bundle     {} ({} certs)", b.path, b.certs);
            }
        }
        for e in &self.errors {
            let _ = writeln!(s, "error      {}: {}", e.path, e.error);
        }
        let _ = writeln!(
            s,
            "{} trust stores still trust a revoked CA; {} findings need review",
            self.failing(),
            self.findings.iter().filter(|x| x.verdict == Verdict::Review && !x.superseded).count()
        );
        s
    }

    pub fn sarif(&self) -> serde_json::Value {
        let results: Vec<serde_json::Value> = self
            .findings
            .iter()
            .filter(|x| !x.superseded)
            .flat_map(|x| {
                let (rule, level) = match x.verdict {
                    Verdict::Trusts => ("trusts-revoked-ca", "error"),
                    Verdict::Review => ("contains-revoked-ca", "warning"),
                };
                let uri = x.path.split("!/").next().unwrap_or(&x.path).to_string();
                x.matches.iter().map(move |mo| {
                    let mut msg = format!("{}: {} ({}). {}", x.path, mo.name, mo.source, x.reason);
                    if let Some(o) = &x.owner {
                        let _ = write!(msg, ". Package {} {} {}", o.ecosystem, o.name, o.version.as_deref().unwrap_or(""));
                    }
                    if let Some(fix) = x.fix.as_ref().filter(|f| !f.fixed.is_empty()) {
                        let _ = write!(msg, ", upgrade to {}", fix.fixed.join(" / "));
                    }
                    let region = if x.path.contains("!/") {
                        json!({})
                    } else {
                        json!({"byteOffset": mo.offset, "byteLength": mo.len})
                    };
                    json!({
                        "ruleId": rule,
                        "level": level,
                        "message": {"text": msg},
                        "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}, "region": region}}],
                        "partialFingerprints": {"certificate": mo.cert_sha256.clone().unwrap_or_else(|| mo.name.clone())}
                    })
                })
            })
            .collect();
        json!({
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {
                    "name": "trustsweep",
                    "version": self.version,
                    "rules": [
                        {"id": "trusts-revoked-ca", "shortDescription": {"text": "CA bundle still trusts a root that issued or cross-signed a revoked CA"}, "defaultConfiguration": {"level": "error"}},
                        {"id": "contains-revoked-ca", "shortDescription": {"text": "File contains a revoked CA certificate or a root Mozilla removed"}, "defaultConfiguration": {"level": "warning"}}
                    ]
                }},
                "results": results
            }]
        })
    }
}
