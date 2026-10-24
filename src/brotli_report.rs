//! Verdicts and output for `brotlisweep`, following the conventions of `report`.

use serde::Serialize;
use serde_json::json;
use std::collections::HashMap;
use std::fmt::Write;

use crate::attribute::{Owner, attribute};
use crate::brotli::{Claim, Rules, Status, VersionEvidence, judge};
use crate::registry::Pulled;
use crate::scan::{ScanError, Scanner, Stats};

#[derive(Debug, Clone, Serialize)]
pub struct SliceOut {
    pub arch: String,
    pub offset: usize,
    pub controls: usize,
    pub markers: usize,
    pub status: Status,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claim: Option<Claim>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<VersionEvidence>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DecoderFinding {
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub layer: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub layer_digest: Option<String>,
    pub status: Status,
    pub reason: String,
    pub superseded: bool,
    pub slices: Vec<SliceOut>,
    pub owner: Option<Owner>,
    /// HTTP clients in the same Python environment that will ask servers for Brotli.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub http_clients: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct RulesInfo {
    pub id: String,
    pub advisory: String,
    pub snapshot: String,
}

#[derive(Debug, Serialize)]
pub struct BrotliReport {
    pub tool: &'static str,
    pub version: &'static str,
    pub rules: RulesInfo,
    pub stats: Stats,
    pub findings: Vec<DecoderFinding>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub layers: Vec<String>,
    pub errors: Vec<ScanError>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<Pulled>,
}

/// `name-1.2.3.dist-info/RECORD` → (`name`, `1.2.3`), name lowercased.
fn dist_of(record_key: &str) -> Option<(String, String)> {
    let dir = record_key.strip_suffix(".dist-info/RECORD")?;
    let stem = dir.rsplit('/').next()?;
    let (name, version) = stem.split_once('-')?;
    Some((name.to_ascii_lowercase().replace('_', "-"), version.to_string()))
}

/// HTTP clients installed next to the Brotli package whose RECORD is `record_key`.
fn clients_beside(record_key: &str, store: &HashMap<String, Vec<u8>>, rules: &Rules) -> Vec<String> {
    let Some(site) = record_key.rsplit_once('/').and_then(|(d, _)| d.rsplit_once('/')).map(|(s, _)| s) else {
        return Vec::new();
    };
    let mut found: Vec<String> = store
        .keys()
        .filter(|k| k.strip_prefix(site).is_some_and(|r| r.matches('/').count() == 2))
        .filter_map(|k| dist_of(k))
        .filter(|(n, _)| rules.http_clients.contains(n))
        .map(|(n, v)| format!("{n} {v}"))
        .collect();
    found.sort();
    found
}

impl BrotliReport {
    pub fn build(scanner: Scanner, rules: &Rules) -> Self {
        let m = scanner.matcher;
        let findings = scanner
            .decoders
            .iter()
            .map(|d| {
                let owner = attribute(&d.path, &scanner.store, &m.binaries);
                let package = owner.as_ref().and_then(|o| {
                    let p = rules
                        .packages
                        .iter()
                        .find(|p| p.ecosystem == o.ecosystem && p.name.eq_ignore_ascii_case(&o.name))?;
                    Some(VersionEvidence::new(&p.name, o.version.as_deref()?, o.evidence.clone(), &p.fixes, &p.source))
                });
                let http_clients = match (&owner, &package) {
                    (Some(o), Some(_)) => clients_beside(&o.evidence, &scanner.store, rules),
                    _ => Vec::new(),
                };
                let slices: Vec<SliceOut> = d
                    .slices
                    .iter()
                    .map(|s| {
                        let version = package.clone().or_else(|| {
                            let c = s.claim.as_ref()?;
                            let p = rules.products.iter().find(|p| p.name == c.product)?;
                            Some(VersionEvidence::new(&p.name, &c.version, "embedded string".into(), &p.fixes, &p.source))
                        });
                        let (status, reason) = judge(s, version.as_ref());
                        SliceOut {
                            arch: s.arch.clone(),
                            offset: s.offset,
                            controls: s.controls,
                            markers: s.markers,
                            status,
                            reason,
                            claim: s.claim.clone(),
                            version,
                        }
                    })
                    .collect();
                let status = if slices.iter().any(|s| s.status == Status::Unfixed) {
                    Status::Unfixed
                } else if slices.iter().all(|s| s.status == Status::Fixed) {
                    Status::Fixed
                } else {
                    Status::Unknown
                };
                let reason = slices
                    .iter()
                    .find(|s| s.status == status)
                    .map(|s| s.reason.clone())
                    .unwrap_or_default();
                DecoderFinding {
                    path: d.path.clone(),
                    layer: d.layer,
                    layer_digest: d.layer.and_then(|l| scanner.layers.get(l).cloned()),
                    status,
                    reason,
                    superseded: d.superseded,
                    slices,
                    owner,
                    http_clients,
                }
            })
            .collect();
        BrotliReport {
            tool: "trustsweep brotli",
            version: env!("CARGO_PKG_VERSION"),
            rules: RulesInfo {
                id: rules.id.clone(),
                advisory: rules.advisory.clone(),
                snapshot: rules.snapshot.clone(),
            },
            stats: scanner.stats,
            findings,
            layers: scanner.layers,
            errors: scanner.errors,
            image: scanner.image,
        }
    }

    fn live(&self, status: Status) -> usize {
        self.findings.iter().filter(|f| f.status == status && !f.superseded).count()
    }

    /// 1 when a live decoder is unfixed, 2 when coverage is incomplete, else 0.
    pub fn exit_code(&self) -> i32 {
        if self.live(Status::Unfixed) > 0 {
            1
        } else if !self.errors.is_empty() {
            2
        } else {
            0
        }
    }

    pub fn text(&self) -> String {
        let mut s = String::new();
        let _ = writeln!(
            s,
            "trustsweep {} brotli | {} (rules {}, snapshot {})",
            self.version, self.rules.advisory, self.rules.id, self.rules.snapshot
        );
        if let Some(i) = &self.image {
            let _ = writeln!(s, "image {} | manifest {} | {} | {} layers", i.source, i.manifest_digest, i.platform.as_deref().unwrap_or("single-platform"), i.layers);
        }
        let _ = writeln!(
            s,
            "scanned {} files, {} archives, {} excluded | {} Brotli decoders found | {} errors\n",
            self.stats.files,
            self.stats.archives,
            self.stats.excluded,
            self.findings.iter().filter(|f| !f.superseded).count(),
            self.errors.len()
        );
        let mut sorted: Vec<&DecoderFinding> = self.findings.iter().collect();
        let rank = |f: &DecoderFinding| match (f.superseded, f.status) {
            (true, _) => 3,
            (_, Status::Unfixed) => 0,
            (_, Status::Unknown) => 1,
            (_, Status::Fixed) => 2,
        };
        sorted.sort_by_key(|f| (rank(f), f.path.clone()));
        for f in sorted {
            let tag = match (f.superseded, f.status) {
                (true, _) => "SUPERSEDED",
                (_, Status::Unfixed) => "UNFIXED",
                (_, Status::Unknown) => "UNKNOWN",
                (_, Status::Fixed) => "FIXED",
            };
            let _ = writeln!(s, "{tag:<10} {}", f.path);
            if let (Some(l), Some(d)) = (f.layer, &f.layer_digest) {
                let _ = writeln!(s, "           layer {l} ({})", d.get(..19).unwrap_or(d));
            }
            let _ = writeln!(s, "           {}", f.reason);
            for sl in &f.slices {
                let v = sl
                    .version
                    .as_ref()
                    .map(|v| format!(", {} {} from {}", v.product, v.version, v.from))
                    .unwrap_or_default();
                let _ = writeln!(
                    s,
                    "           - {}: {} decoder strings, {} fix markers{v} -> {:?}",
                    sl.arch, sl.controls, sl.markers, sl.status
                );
            }
            match &f.owner {
                Some(o) => {
                    let v = o.version.as_deref().unwrap_or("version unknown");
                    let _ = writeln!(s, "           package: {} {} {v}  (from {})", o.ecosystem, o.name, o.evidence);
                }
                None => {
                    let _ = writeln!(s, "           package: unknown");
                }
            }
            let fix = f
                .slices
                .iter()
                .filter(|sl| sl.status != Status::Fixed)
                .find_map(|sl| {
                    let v = sl.version.as_ref()?;
                    Some((v.fixed_in.as_ref()?, &v.product))
                });
            if let Some((fixed, product)) = fix {
                let _ = writeln!(s, "           fix: {product} {fixed} or later");
            }
            if !f.http_clients.is_empty() {
                let _ = writeln!(
                    s,
                    "           reachable: {} in this environment send Accept-Encoding: br when brotli is importable",
                    f.http_clients.join(", ")
                );
            }
            s.push('\n');
        }
        if self.findings.is_empty() {
            s.push_str("no Brotli decoders found\n\n");
        }
        for e in &self.errors {
            let _ = writeln!(s, "error      {}: {}", e.path, e.error);
        }
        let _ = writeln!(
            s,
            "{} unfixed, {} unknown, {} fixed",
            self.live(Status::Unfixed),
            self.live(Status::Unknown),
            self.live(Status::Fixed)
        );
        s
    }

    pub fn sarif(&self) -> serde_json::Value {
        let results: Vec<serde_json::Value> = self
            .findings
            .iter()
            .filter(|f| !f.superseded && f.status != Status::Fixed)
            .map(|f| {
                let (rule, level) = match f.status {
                    Status::Unfixed => ("brotli-unfixed", "error"),
                    _ => ("brotli-unknown", "warning"),
                };
                let mut msg = format!("{}: {}", f.path, f.reason);
                if let Some(o) = &f.owner {
                    let _ = write!(msg, ". Package {} {} {}", o.ecosystem, o.name, o.version.as_deref().unwrap_or(""));
                }
                json!({
                    "ruleId": rule,
                    "level": level,
                    "message": {"text": msg},
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.path.split("!/").next().unwrap_or(&f.path)}}}]
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
                        {"id": "brotli-unfixed", "shortDescription": {"text": "Brotli decoder without the CVE-2026-111497 fix marker, from a release older than the fix"}, "defaultConfiguration": {"level": "error"}},
                        {"id": "brotli-unknown", "shortDescription": {"text": "Brotli decoder whose CVE-2026-111497 fix status cannot be determined"}, "defaultConfiguration": {"level": "warning"}}
                    ]
                }},
                "results": results
            }]
        })
    }
}
