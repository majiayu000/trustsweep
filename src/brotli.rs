//! brotlisweep: find embedded Brotli decoders and judge them by the CVE-2026-111497 fix marker.

use anyhow::{Context, Result};
use memchr::memmem;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;

pub const BUILTIN_RULES: &str = include_str!("../data/brotli.json");

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Product {
    pub name: String,
    /// Text that precedes the product's version inside its own binary, e.g. `bun-v`.
    pub claim: String,
    /// `[branch prefix, first fixed version]` pairs.
    pub fixes: Vec<(String, String)>,
    pub source: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Package {
    pub ecosystem: String,
    pub name: String,
    pub fixes: Vec<(String, String)>,
    pub source: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Rules {
    pub id: String,
    pub advisory: String,
    pub snapshot: String,
    /// Error-code string present in every decoder build, fixed or not.
    pub control: String,
    /// Error-code string added by the fix.
    pub marker: String,
    pub marker_source: String,
    /// Checked in order: Bun, Electron and Deno binaries also carry a Node version string, so they come first.
    pub products: Vec<Product>,
    pub packages: Vec<Package>,
    /// Python HTTP clients that advertise `br` when brotli or brotlicffi is importable.
    pub http_clients: Vec<String>,
}

impl Rules {
    pub fn builtin() -> Result<Self> {
        serde_json::from_str(BUILTIN_RULES).context("data/brotli.json is not valid")
    }
}

/// One architecture slice of a Mach-O universal binary, or the whole file.
#[derive(Debug, Clone, Serialize)]
pub struct Slice {
    pub arch: String,
    pub offset: usize,
    pub controls: usize,
    pub markers: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claim: Option<Claim>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Claim {
    pub product: String,
    pub version: String,
}

fn cpu_name(cputype: u32) -> String {
    match cputype {
        7 => "x86".into(),
        0x0100_0007 => "x86_64".into(),
        12 => "arm".into(),
        0x0100_000c => "arm64".into(),
        0x0200_000c => "arm64_32".into(),
        other => format!("cputype {other:#x}"),
    }
}

fn be32(d: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(d.get(at..at + 4)?.try_into().ok()?))
}

fn be64(d: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_be_bytes(d.get(at..at + 8)?.try_into().ok()?))
}

/// Byte ranges of a universal (fat) Mach-O's slices, or None for any other file.
pub fn fat_slices(d: &[u8]) -> Option<Vec<(String, usize, usize)>> {
    let (wide, entry) = match be32(d, 0)? {
        0xcafe_babe => (false, 20),
        0xcafe_babf => (true, 32),
        _ => return None,
    };
    let n = be32(d, 4)? as usize;
    // Java class files share 0xcafebabe; their next word is a class-file version >= 45.
    if n == 0 || n >= 30 {
        return None;
    }
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let at = 8 + i * entry;
        let cpu = be32(d, at)?;
        let (offset, size) = if wide {
            (be64(d, at + 8)? as usize, be64(d, at + 16)? as usize)
        } else {
            (be32(d, at + 8)? as usize, be32(d, at + 12)? as usize)
        };
        if offset.checked_add(size)? > d.len() {
            return None;
        }
        out.push((cpu_name(cpu), offset, size));
    }
    Some(out)
}

/// The product's version as its own binary states it; the most frequent one wins, since
/// binaries also mention versions of other components (Deno carries an old `Deno/0.x`).
fn claim_in(data: &[u8], rules: &Rules) -> Option<Claim> {
    for p in &rules.products {
        let mut counts: Vec<(String, usize)> = Vec::new();
        for at in memmem::find_iter(data, p.claim.as_bytes()) {
            let rest = &data[at + p.claim.len()..];
            let len = rest
                .iter()
                .take(32)
                .take_while(|b| b.is_ascii_digit() || **b == b'.')
                .count();
            let Ok(version) = std::str::from_utf8(&rest[..len]) else {
                continue;
            };
            let version = version.trim_end_matches('.');
            if version.split('.').count() < 3 {
                continue;
            }
            match counts.iter_mut().find(|(v, _)| v == version) {
                Some((_, n)) => *n += 1,
                None => counts.push((version.to_string(), 1)),
            }
        }
        if let Some((version, _)) = counts.into_iter().max_by_key(|(_, n)| *n) {
            return Some(Claim {
                product: p.name.clone(),
                version,
            });
        }
    }
    None
}

/// Decoder evidence per slice; empty when the file has no Brotli decoder strings.
pub fn inspect(data: &[u8], rules: &Rules) -> Vec<Slice> {
    let ranges = fat_slices(data).unwrap_or_else(|| vec![("file".into(), 0, data.len())]);
    let slices: Vec<Slice> = ranges
        .into_iter()
        .map(|(arch, offset, size)| {
            let s = &data[offset..offset + size];
            Slice {
                arch,
                offset,
                controls: memmem::find_iter(s, rules.control.as_bytes()).count(),
                markers: memmem::find_iter(s, rules.marker.as_bytes()).count(),
                claim: claim_in(s, rules),
            }
        })
        .collect();
    if slices.iter().all(|s| s.controls == 0 && s.markers == 0) {
        return Vec::new();
    }
    slices
}

/// Numeric dotted-version comparison; None when either side has a non-numeric part.
pub fn compare(a: &str, b: &str) -> Option<Ordering> {
    let parse = |v: &str| v.split('.').map(|p| p.parse::<u64>().ok()).collect::<Option<Vec<u64>>>();
    let (a, b) = (parse(a)?, parse(b)?);
    Some(a.cmp(&b))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Fixed,
    Unfixed,
    Unknown,
}

/// A version that says whether the decoder should be fixed, and where it came from.
#[derive(Debug, Clone, Serialize)]
pub struct VersionEvidence {
    pub product: String,
    pub version: String,
    /// `embedded string` or the metadata file it was read from.
    pub from: String,
    /// First fixed release on this version's branch, if one is listed.
    pub fixed_in: Option<String>,
    pub source: String,
}

impl VersionEvidence {
    pub fn new(product: &str, version: &str, from: String, fixes: &[(String, String)], source: &str) -> Self {
        let fixed_in = fixes
            .iter()
            .find(|(prefix, _)| version.starts_with(prefix.as_str()))
            .map(|(_, f)| f.clone());
        Self {
            product: product.to_string(),
            version: version.to_string(),
            from,
            fixed_in,
            source: source.to_string(),
        }
    }

    fn below_fix(&self) -> Option<bool> {
        let fixed = self.fixed_in.as_deref()?;
        Some(compare(&self.version, fixed)? == Ordering::Less)
    }
}

/// The marker decides "fixed"; "unfixed" also needs a version older than its branch fix.
pub fn judge(slice: &Slice, version: Option<&VersionEvidence>) -> (Status, String) {
    if slice.markers > 0 {
        let mut reason = String::from(
            "fix marker present: the error code added by google/brotli@0ed4268a is compiled in (string evidence, not a code-level proof)",
        );
        if slice.controls > slice.markers {
            reason.push_str("; more decoder strings than markers, so check whether the file bundles a second decoder copy");
        }
        return (Status::Fixed, reason);
    }
    match version.map(|v| (v, v.below_fix())) {
        Some((v, Some(true))) => (
            Status::Unfixed,
            format!(
                "decoder without the fix marker, and {} {} predates the fixed {}",
                v.product,
                v.version,
                v.fixed_in.as_deref().unwrap_or("?")
            ),
        ),
        Some((v, Some(false))) => (
            Status::Unknown,
            format!("{} {} is a fixed release but the fix marker is absent; verify the build", v.product, v.version),
        ),
        Some((v, None)) => (
            Status::Unknown,
            format!("decoder without the fix marker; no fixed release listed for {} {}", v.product, v.version),
        ),
        None => (
            Status::Unknown,
            "decoder without the fix marker and no version evidence; a missing string alone does not prove the copy is vulnerable".into(),
        ),
    }
}
