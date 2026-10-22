//! Walk directories, archives and image layers; hand every file's bytes to the extractor.

use aho_corasick::AhoCorasick;
use anyhow::{Context, Result, anyhow, bail};
use flate2::read::GzDecoder;
use globset::GlobSet;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader, Cursor, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use crate::extract::{Encoding, find_certs};
use crate::feed::{MatchedBy, Matcher};

const MAX_DEPTH: usize = 4;
const MAX_ARCHIVE_ENTRIES: usize = 200_000;
/// Package metadata (dpkg status, RECORD, package.json...) is kept in memory for attribution.
const MAX_META_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, Serialize)]
pub struct Hit {
    pub target: usize,
    pub matched_by: MatchedBy,
    pub encoding: Option<Encoding>,
    pub offset: usize,
    pub len: usize,
    pub cert_sha256: Option<String>,
}

#[derive(Debug, Clone)]
pub struct FileHits {
    pub path: String,
    pub layer: Option<usize>,
    pub cert_count: usize,
    pub hits: Vec<Hit>,
    pub superseded: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Bundle {
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub layer: Option<usize>,
    pub certs: usize,
    pub superseded: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanError {
    pub path: String,
    pub error: String,
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct Stats {
    pub files: usize,
    pub archives: usize,
    pub excluded: usize,
}

#[derive(Default)]
struct LayerPaths {
    files: HashSet<String>,
    whiteouts: HashSet<String>,
    opaque_dirs: HashSet<String>,
}

pub struct Scanner<'a> {
    pub matcher: &'a Matcher,
    keys: AhoCorasick,
    excludes: GlobSet,
    max_file_bytes: u64,
    skip_exe: Option<PathBuf>,
    current_layer: Option<usize>,
    layer_paths: Vec<LayerPaths>,
    pub layers: Vec<String>,
    pub stats: Stats,
    pub hit_files: Vec<FileHits>,
    pub bundles: Vec<Bundle>,
    pub errors: Vec<ScanError>,
    pub store: HashMap<String, Vec<u8>>,
}

enum ArchiveKind {
    Zip,
    Tar,
    TarGz,
}

fn archive_kind(path: &str) -> Option<ArchiveKind> {
    let lower = path.to_ascii_lowercase();
    let ext = |e: &str| lower.ends_with(e);
    if [".whl", ".jar", ".war", ".ear", ".zip", ".nupkg", ".egg", ".aar"].iter().any(|e| ext(e)) {
        Some(ArchiveKind::Zip)
    } else if [".tgz", ".tar.gz", ".crate"].iter().any(|e| ext(e)) {
        Some(ArchiveKind::TarGz)
    } else if [".tar", ".gem"].iter().any(|e| ext(e)) {
        Some(ArchiveKind::Tar)
    } else {
        None
    }
}

/// Files that `attribute` reads to decide which package owns a CA bundle.
pub fn is_meta(path: &str) -> bool {
    if path.ends_with(".dist-info/RECORD")
        || path.ends_with("/release")
        || path.ends_with("var/lib/dpkg/status")
        || path.ends_with("lib/apk/db/installed")
        || (path.contains("var/lib/dpkg/info/") && path.ends_with(".list"))
        || path.contains("var/lib/dpkg/status.d/")
        || (path.contains("META-INF/maven/") && path.ends_with("/pom.properties"))
    {
        return true;
    }
    // node_modules/<pkg>/package.json or node_modules/@scope/<pkg>/package.json
    if let Some(rest) = path.rsplit_once("node_modules/").map(|(_, r)| r) {
        let parts: Vec<&str> = rest.split('/').collect();
        return matches!(parts.as_slice(), [_, "package.json"])
            || matches!(parts.as_slice(), [s, _, "package.json"] if s.starts_with('@'));
    }
    false
}

fn parent(path: &str) -> &str {
    path.rsplit_once('/').map(|(p, _)| p).unwrap_or("")
}

impl<'a> Scanner<'a> {
    pub fn new(matcher: &'a Matcher, excludes: GlobSet, max_file_bytes: u64) -> Result<Self> {
        let keys = AhoCorasick::new(matcher.key_patterns.iter().map(|(k, _)| k))
            .context("building key-bytes matcher")?;
        Ok(Self {
            matcher,
            keys,
            excludes,
            max_file_bytes,
            skip_exe: std::env::current_exe().ok().and_then(|p| p.canonicalize().ok()),
            current_layer: None,
            layer_paths: Vec::new(),
            layers: Vec::new(),
            stats: Stats::default(),
            hit_files: Vec::new(),
            bundles: Vec::new(),
            errors: Vec::new(),
            store: HashMap::new(),
        })
    }

    fn error(&mut self, path: &str, err: impl std::fmt::Display) {
        self.errors.push(ScanError {
            path: path.to_string(),
            error: err.to_string(),
        });
    }

    /// Scan a file or a directory tree on disk.
    pub fn scan_path(&mut self, root: &Path) {
        for entry in walkdir::WalkDir::new(root).follow_links(false) {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    let p = e.path().map(|p| p.display().to_string()).unwrap_or_default();
                    self.error(&p, e);
                    continue;
                }
            };
            if !entry.file_type().is_file() && !(entry.depth() == 0 && entry.path().is_file()) {
                continue;
            }
            let path = entry.path();
            let display = path.display().to_string();
            if self.excludes.is_match(&display) {
                self.stats.excluded += 1;
                continue;
            }
            if let (Some(exe), Ok(canon)) = (&self.skip_exe, path.canonicalize())
                && *exe == canon
            {
                // Our own binary embeds the feed.
                self.stats.excluded += 1;
                continue;
            }
            let size = match path.metadata() {
                Ok(m) => m.len(),
                Err(e) => {
                    self.error(&display, e);
                    continue;
                }
            };
            if size > self.max_file_bytes {
                self.error(&display, format!("file is {size} bytes, over --max-file-bytes"));
                continue;
            }
            match std::fs::read(path) {
                Ok(data) => self.scan_bytes(&display, &data, 0),
                Err(e) => self.error(&display, e),
            }
        }
    }

    pub fn scan_bytes(&mut self, path: &str, data: &[u8], depth: usize) {
        if depth > 0 && self.excludes.is_match(path) {
            self.stats.excluded += 1;
            return;
        }
        if is_meta(path) && data.len() <= MAX_META_BYTES {
            self.store.insert(path.to_string(), data.to_vec());
        }
        if depth < MAX_DEPTH
            && let Some(kind) = archive_kind(path)
        {
            match self.scan_archive(path, data, kind, depth) {
                Ok(()) => {
                    self.stats.archives += 1;
                    return;
                }
                Err(e) => self.error(path, format!("not scanned as archive ({e:#}); scanned as plain bytes")),
            }
        }
        self.stats.files += 1;
        self.scan_content(path, data);
    }

    fn scan_content(&mut self, path: &str, data: &[u8]) {
        let certs = find_certs(data);
        let unique: HashSet<[u8; 32]> = certs.iter().map(|c| c.sha256_bytes).collect();
        let mut hits = Vec::new();
        let mut seen_targets = HashSet::new();
        let mut covered_keys = HashSet::new();
        for c in &certs {
            if let Some(k) = self.matcher.key_patterns.iter().position(|(k, _)| *k == c.public_key) {
                covered_keys.insert(k);
            }
            if let Some((target, matched_by)) = self.matcher.match_cert(c)
                && seen_targets.insert(target)
            {
                hits.push(Hit {
                    target,
                    matched_by,
                    encoding: Some(c.encoding),
                    offset: c.offset,
                    len: c.len,
                    cert_sha256: Some(c.sha256.clone()),
                });
            }
        }
        // Trust anchors stored as bare keys (webpki-roots) leave no certificate to parse.
        for m in self.keys.find_iter(data) {
            let k = m.pattern().as_usize();
            if !covered_keys.insert(k) {
                continue;
            }
            let target = self.matcher.key_patterns[k].1;
            if seen_targets.insert(target) {
                hits.push(Hit {
                    target,
                    matched_by: MatchedBy::EmbeddedKey,
                    encoding: None,
                    offset: m.start(),
                    len: m.len(),
                    cert_sha256: None,
                });
            }
        }
        // JAR signature blocks carry the signer's chain, not a trust store.
        let signature_block = path.contains("META-INF/")
            && [".RSA", ".DSA", ".EC"].iter().any(|e| path.ends_with(e));
        if unique.len() >= 2 && !signature_block {
            self.bundles.push(Bundle {
                path: path.to_string(),
                layer: self.current_layer,
                certs: unique.len(),
                superseded: false,
            });
        }
        if !hits.is_empty() {
            self.hit_files.push(FileHits {
                path: path.to_string(),
                layer: self.current_layer,
                cert_count: unique.len(),
                hits,
                superseded: false,
            });
        }
    }

    fn scan_archive(&mut self, path: &str, data: &[u8], kind: ArchiveKind, depth: usize) -> Result<()> {
        match kind {
            ArchiveKind::Zip => {
                let mut zip = zip::ZipArchive::new(Cursor::new(data))?;
                if zip.len() > MAX_ARCHIVE_ENTRIES {
                    bail!("{} entries, over the cap of {MAX_ARCHIVE_ENTRIES}", zip.len());
                }
                for i in 0..zip.len() {
                    let mut entry = match zip.by_index(i) {
                        Ok(e) => e,
                        Err(e) => {
                            self.error(path, format!("entry {i}: {e}"));
                            continue;
                        }
                    };
                    if !entry.is_file() {
                        continue;
                    }
                    let name = match entry.name() {
                        Ok(n) => n.into_owned(),
                        Err(e) => {
                            self.error(path, format!("entry {i}: {e}"));
                            continue;
                        }
                    };
                    let member = format!("{path}!/{name}");
                    if entry.size() > self.max_file_bytes {
                        self.error(&member, "entry over --max-file-bytes");
                        continue;
                    }
                    let mut buf = Vec::with_capacity(entry.size() as usize);
                    if let Err(e) = entry.read_to_end(&mut buf) {
                        self.error(&member, e);
                        continue;
                    }
                    drop(entry);
                    self.scan_bytes(&member, &buf, depth + 1);
                }
                Ok(())
            }
            ArchiveKind::Tar => self.scan_tar(path, Cursor::new(data), depth),
            ArchiveKind::TarGz => self.scan_tar(path, GzDecoder::new(Cursor::new(data)), depth),
        }
    }

    fn scan_tar<R: Read>(&mut self, path: &str, reader: R, depth: usize) -> Result<()> {
        let mut archive = tar::Archive::new(reader);
        for (n, entry) in archive.entries()?.enumerate() {
            if n >= MAX_ARCHIVE_ENTRIES {
                bail!("over the cap of {MAX_ARCHIVE_ENTRIES} entries");
            }
            let mut entry = entry?;
            if !entry.header().entry_type().is_file() {
                continue;
            }
            let name = entry.path()?.to_string_lossy().trim_start_matches("./").to_string();
            let member = format!("{path}!/{name}");
            if entry.size() > self.max_file_bytes {
                self.error(&member, "entry over --max-file-bytes");
                continue;
            }
            let mut buf = Vec::new();
            entry.read_to_end(&mut buf)?;
            self.scan_bytes(&member, &buf, depth + 1);
        }
        Ok(())
    }

    /// Scan a `docker save` / OCI tarball layer by layer.
    pub fn scan_image(&mut self, tarball: &Path) -> Result<()> {
        let mut index: HashMap<String, (u64, u64)> = HashMap::new();
        let mut manifest = None;
        {
            let file = File::open(tarball).with_context(|| format!("opening {}", tarball.display()))?;
            let mut outer = tar::Archive::new(file);
            for entry in outer.entries()? {
                let mut entry = entry?;
                let name = entry.path()?.to_string_lossy().trim_start_matches("./").to_string();
                if name == "manifest.json" {
                    let mut s = String::new();
                    entry.read_to_string(&mut s)?;
                    manifest = Some(s);
                }
                index.insert(name, (entry.raw_file_position(), entry.size()));
            }
        }
        let manifest = manifest.ok_or_else(|| anyhow!("no manifest.json: not a docker save / OCI tarball"))?;
        let manifest: serde_json::Value = serde_json::from_str(&manifest).context("parsing manifest.json")?;
        let layers: Vec<String> = manifest
            .get(0)
            .and_then(|m| m.get("Layers"))
            .and_then(|l| l.as_array())
            .ok_or_else(|| anyhow!("manifest.json has no Layers"))?
            .iter()
            .map(|v| v.as_str().map(str::to_string).ok_or_else(|| anyhow!("layer entry is not a string")))
            .collect::<Result<_>>()?;

        let mut file = File::open(tarball)?;
        for (li, layer) in layers.iter().enumerate() {
            let &(pos, size) = index
                .get(layer.as_str())
                .ok_or_else(|| anyhow!("layer {layer} listed in manifest but missing from tarball"))?;
            file.seek(SeekFrom::Start(pos))?;
            let mut reader = BufReader::new((&mut file).take(size));
            let magic = reader.fill_buf()?.get(..4).map(<[u8]>::to_vec).unwrap_or_default();
            self.current_layer = Some(li);
            self.layers.push(layer_digest(layer));
            self.layer_paths.push(LayerPaths::default());
            let result = match magic.as_slice() {
                [0x1f, 0x8b, ..] => self.scan_layer(GzDecoder::new(reader), li),
                [0x28, 0xb5, 0x2f, 0xfd] => ruzstd::decoding::StreamingDecoder::new(reader)
                    .map_err(|e| anyhow!("zstd: {e}"))
                    .and_then(|d| self.scan_layer(d, li)),
                _ => self.scan_layer(reader, li),
            };
            result.with_context(|| format!("layer {li} ({layer})"))?;
        }
        self.current_layer = None;
        self.mark_superseded();
        Ok(())
    }

    fn scan_layer<R: Read>(&mut self, reader: R, li: usize) -> Result<()> {
        let mut archive = tar::Archive::new(reader);
        for entry in archive.entries()? {
            let mut entry = entry?;
            let rel = entry.path()?.to_string_lossy().trim_start_matches("./").trim_end_matches('/').to_string();
            let path = format!("/{rel}");
            let (dir, base) = path.rsplit_once('/').unwrap_or(("", &path));
            if base == ".wh..wh..opq" {
                self.layer_paths[li].opaque_dirs.insert(dir.to_string());
                let prefix = format!("{dir}/");
                self.store.retain(|k, _| !k.starts_with(&prefix));
                continue;
            }
            if let Some(name) = base.strip_prefix(".wh.") {
                let gone = format!("{dir}/{name}");
                let prefix = format!("{gone}/");
                self.store.retain(|k, _| *k != gone && !k.starts_with(&prefix));
                self.layer_paths[li].whiteouts.insert(gone);
                continue;
            }
            self.layer_paths[li].files.insert(path.clone());
            if !entry.header().entry_type().is_file() {
                continue;
            }
            if self.excludes.is_match(&path) {
                self.stats.excluded += 1;
                continue;
            }
            if entry.size() > self.max_file_bytes {
                self.error(&path, "entry over --max-file-bytes");
                continue;
            }
            let mut buf = Vec::new();
            entry.read_to_end(&mut buf)?;
            self.scan_bytes(&path, &buf, 0);
        }
        Ok(())
    }

    fn hidden_later(&self, layer: usize, path: &str) -> bool {
        self.layer_paths.iter().skip(layer + 1).any(|lp| {
            if lp.files.contains(path) {
                return true;
            }
            let mut p = path;
            loop {
                if lp.whiteouts.contains(p) {
                    return true;
                }
                p = parent(p);
                if lp.opaque_dirs.contains(p) {
                    return true;
                }
                if p.is_empty() {
                    return false;
                }
            }
        })
    }

    fn mark_superseded(&mut self) {
        // Nested archive members are hidden when the outer file is.
        let outer = |p: &str| p.split("!/").next().unwrap_or(p).to_string();
        let flags: Vec<bool> = self
            .hit_files
            .iter()
            .map(|h| h.layer.is_some_and(|l| self.hidden_later(l, &outer(&h.path))))
            .collect();
        for (h, f) in self.hit_files.iter_mut().zip(flags) {
            h.superseded = f;
        }
        let flags: Vec<bool> = self
            .bundles
            .iter()
            .map(|b| b.layer.is_some_and(|l| self.hidden_later(l, &outer(&b.path))))
            .collect();
        for (b, f) in self.bundles.iter_mut().zip(flags) {
            b.superseded = f;
        }
    }
}

fn layer_digest(layer: &str) -> String {
    match layer.strip_prefix("blobs/sha256/") {
        Some(hex) => format!("sha256:{hex}"),
        None => layer.to_string(),
    }
}
