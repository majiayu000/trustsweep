//! Offline tests for the generalized feed (OneCRL + CCADB samples) and for image pulls,
//! using a synthetic OCI image layout instead of a registry.

use flate2::{Compression, write::GzEncoder};
use globset::GlobSet;
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::Path;
use trustsweep::extract::parse_pem_blocks;
use trustsweep::feed::{Feed, FeedCert, RemovedRoot, Role, Sources, build, parse_removed};
use trustsweep::registry::{OciLayout, Platform, credentials_from_config, parse_challenge, parse_ref, pull_and_scan};
use trustsweep::report::{Report, Verdict};
use trustsweep::scan::Scanner;

const ONECRL: &str = include_str!("fixtures/onecrl-sample.json");
const REMOVED: &str = include_str!("fixtures/ccadb-removed-sample.csv");

fn ca(cn: &str) -> String {
    let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.distinguished_name.push(DnType::CommonName, cn);
    p.self_signed(&KeyPair::generate().unwrap()).unwrap().pem()
}

fn builtin() -> Feed {
    Feed::load(Some(Path::new("data/feed.json"))).unwrap().0
}

fn empty_feed() -> Feed {
    Feed {
        id: "t".into(),
        generated_at: "t".into(),
        sources: vec![],
        certs: vec![],
        onecrl: vec![],
        removed: vec![],
        fixes: vec![],
        binaries: vec![],
    }
}

fn incident_json(certs: &[FeedCert], role: Role) -> String {
    let list: Vec<_> = certs
        .iter()
        .filter(|c| c.role == role)
        .map(|c| json!({"name": c.name, "sha256": c.sha256, "spki_sha256": c.spki_sha256, "pem": c.pem}))
        .collect();
    serde_json::to_string(&list).unwrap()
}

#[test]
fn ccadb_report_is_parsed_and_expired_roots_dropped() {
    let now = parse_removed(REMOVED, "2026-10-25").unwrap();
    assert_eq!(now.len(), 3);
    let g3 = now.iter().find(|r| r.name == "emSign ECC Root CA - G3").unwrap();
    assert_eq!(g3.sha256, "86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B");
    assert_eq!(g3.valid_to, "2043-02-18");
    assert!(now.iter().all(|r| r.nss_removed.starts_with("NSS ")));
    // CNNIC ROOT expires 2027-04-16.
    assert_eq!(parse_removed(REMOVED, "2028-01-01").unwrap().len(), 2);
}

#[test]
fn ccadb_report_with_changed_columns_is_an_error() {
    let err = parse_removed("\"Name\",\"Fingerprint\"\n\"x\",\"y\"\n", "2026-10-25").unwrap_err();
    assert!(err.to_string().contains("format changed"), "{err}");
}

#[test]
fn feed_build_keeps_the_incident_and_adds_onecrl_and_ccadb() {
    let base = builtin();
    let src = Sources {
        roots_json: incident_json(&base.certs, Role::Root),
        intermediates_json: incident_json(&base.certs, Role::Revoked),
        onecrl_json: ONECRL.to_string(),
        removed_csv: REMOVED.to_string(),
        urls: vec!["fixture".into()],
    };
    let feed = build(&base, src, "2026-10-25T00:00:00Z".into()).unwrap();
    assert_eq!(feed.certs.len(), 20, "4 eMudhra-related roots and 16 revoked intermediates stay");
    assert_eq!(feed.onecrl.len(), 2, "the disabled OneCRL record is dropped");
    assert_eq!(feed.removed.len(), 3);
    assert_eq!(feed.fixes.len(), base.fixes.len());

    let m = feed.compile("t".into()).unwrap();
    // emSign ECC Root CA - G3 is both an incident root and a CCADB removal: the incident role wins.
    let g3 = feed.certs.iter().find(|c| c.name == "emSign ECC Root CA - G3").unwrap();
    let parsed = parse_pem_blocks(g3.pem.as_bytes());
    let (t, _) = m.match_cert(&parsed[0]).unwrap();
    assert_eq!(m.targets[t].role, Role::Root);
    assert_eq!(m.targets.iter().filter(|t| t.role == Role::Removed).count(), 2);
}

#[test]
fn feed_build_refuses_an_empty_source() {
    let base = builtin();
    let src = Sources {
        roots_json: incident_json(&base.certs, Role::Root),
        intermediates_json: incident_json(&base.certs, Role::Revoked),
        onecrl_json: r#"{"changes": []}"#.into(),
        removed_csv: REMOVED.to_string(),
        urls: vec![],
    };
    assert!(build(&base, src, "2026-10-25T00:00:00Z".into()).is_err());
}

#[test]
fn bundle_with_a_removed_root_is_review_not_failure() {
    let removed_pem = ca("Test Retired Root");
    let benign = ca("Test Benign Root");
    let sha = parse_pem_blocks(removed_pem.as_bytes())[0].sha256.clone();
    let mut feed = empty_feed();
    feed.removed.push(RemovedRoot {
        name: "Test Retired Root".into(),
        sha256: sha,
        nss_removed: "NSS 3.123".into(),
        valid_to: "2040-01-01".into(),
        bug: "1".into(),
    });
    let m = feed.compile("t".into()).unwrap();
    let mut s = Scanner::new(&m, GlobSet::empty(), 1 << 30).unwrap();
    s.scan_bytes("/etc/ssl/cert.pem", format!("{benign}{removed_pem}").as_bytes(), 0);
    let r = Report::build(s);
    assert_eq!(r.findings[0].verdict, Verdict::Review);
    assert_eq!(r.findings[0].matches[0].role, Role::Removed);
    assert!(r.findings[0].matches[0].name.contains("NSS 3.123"));
    assert_eq!(r.exit_code(), 0);
}

#[test]
fn image_references_parse() {
    let r = parse_ref("alpine").unwrap();
    assert_eq!((r.registry.as_str(), r.repository.as_str(), r.reference.as_str()), ("registry-1.docker.io", "library/alpine", "latest"));
    let r = parse_ref("docker.io/bitnami/redis:7.2").unwrap();
    assert_eq!((r.registry.as_str(), r.repository.as_str(), r.reference.as_str()), ("registry-1.docker.io", "bitnami/redis", "7.2"));
    let r = parse_ref("ghcr.io/o/r@sha256:abc").unwrap();
    assert_eq!((r.registry.as_str(), r.repository.as_str(), r.reference.as_str()), ("ghcr.io", "o/r", "sha256:abc"));
    let r = parse_ref("localhost:5000/app").unwrap();
    assert_eq!((r.registry.as_str(), r.reference.as_str()), ("localhost:5000", "latest"));
}

#[test]
fn bearer_challenge_parses() {
    let (scheme, p) = parse_challenge(r#"Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/alpine:pull""#).unwrap();
    assert_eq!(scheme, "bearer");
    assert_eq!(p[0], ("realm".into(), "https://auth.docker.io/token".into()));
    assert_eq!(p[2], ("scope".into(), "repository:library/alpine:pull".into()));
}

#[test]
fn docker_config_credentials() {
    let cfg = r#"{"auths": {"ghcr.io": {"auth": "dXNlcjpwYXNz"}, "https://index.docker.io/v1/": {"auth": "aHViOnRva2Vu"}}, "credsStore": "desktop"}"#;
    assert_eq!(credentials_from_config(cfg, "ghcr.io").unwrap(), Some(("user".into(), "pass".into())));
    assert_eq!(credentials_from_config(cfg, "registry-1.docker.io").unwrap(), Some(("hub".into(), "token".into())));
    assert_eq!(credentials_from_config(cfg, "quay.io").unwrap(), None);
}

/// Write `data` as a content-addressed blob and return its descriptor.
fn put_blob(dir: &Path, media_type: &str, data: &[u8]) -> serde_json::Value {
    let hex = hex::encode(Sha256::digest(data));
    std::fs::write(dir.join("blobs/sha256").join(&hex), data).unwrap();
    json!({"mediaType": media_type, "digest": format!("sha256:{hex}"), "size": data.len()})
}

fn layer_with(path: &str, content: &[u8]) -> Vec<u8> {
    let mut b = tar::Builder::new(Vec::new());
    let mut h = tar::Header::new_gnu();
    h.set_size(content.len() as u64);
    h.set_mode(0o644);
    h.set_cksum();
    b.append_data(&mut h, path, content).unwrap();
    let mut gz = GzEncoder::new(Vec::new(), Compression::fast());
    gz.write_all(&b.into_inner().unwrap()).unwrap();
    gz.finish().unwrap()
}

/// A two-platform OCI layout: amd64 ships a bundle with `bad`, arm64 a clean one.
fn layout(dir: &Path, bad: &str, clean: &str) {
    std::fs::create_dir_all(dir.join("blobs/sha256")).unwrap();
    std::fs::write(dir.join("oci-layout"), r#"{"imageLayoutVersion":"1.0.0"}"#).unwrap();
    let config = put_blob(dir, "application/vnd.oci.image.config.v1+json", b"{}");
    let mut entries = Vec::new();
    for (arch, bundle) in [("amd64", bad), ("arm64", clean)] {
        let layer = put_blob(dir, "application/vnd.oci.image.layer.v1.tar+gzip", &layer_with("etc/ssl/certs/ca-certificates.crt", bundle.as_bytes()));
        let manifest = json!({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json", "config": config, "layers": [layer]});
        let mut desc = put_blob(dir, "application/vnd.oci.image.manifest.v1+json", manifest.to_string().as_bytes());
        desc["platform"] = json!({"os": "linux", "architecture": arch});
        entries.push(desc);
    }
    let index = json!({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": entries});
    std::fs::write(dir.join("index.json"), index.to_string()).unwrap();
}

fn scan_layout(dir: &Path, platform: &str, feed: &Feed) -> anyhow::Result<Report> {
    let m = feed.compile("t".into())?;
    let mut s = Scanner::new(&m, GlobSet::empty(), 1 << 30)?;
    let pulled = pull_and_scan(&mut OciLayout { dir: dir.to_path_buf() }, "", &Platform::parse(platform)?, &mut s)?;
    assert_eq!(pulled.platform.as_deref(), Some(platform));
    s.image = Some(pulled);
    Ok(Report::build(s))
}

fn root_feed(pem: &str) -> Feed {
    let c = &parse_pem_blocks(pem.as_bytes())[0];
    let mut f = empty_feed();
    f.certs.push(FeedCert {
        name: "Test Distrusted Root".into(),
        role: Role::Root,
        sha256: c.sha256.clone(),
        spki_sha256: c.spki_sha256.clone(),
        pem: pem.into(),
    });
    f
}

#[test]
fn oci_layout_selects_the_requested_platform() {
    let (bad_root, benign) = (ca("Test Distrusted Root"), ca("Test Benign Root"));
    let dir = tempfile::tempdir().unwrap();
    layout(dir.path(), &format!("{benign}{bad_root}"), &format!("{benign}{benign}"));
    let feed = root_feed(&bad_root);

    let amd = scan_layout(dir.path(), "linux/amd64", &feed).unwrap();
    assert_eq!(amd.findings.len(), 1);
    assert_eq!(amd.findings[0].verdict, Verdict::Trusts);
    assert_eq!(amd.findings[0].layer, Some(0));
    assert!(amd.image.as_ref().unwrap().manifest_digest.starts_with("sha256:"));

    let arm = scan_layout(dir.path(), "linux/arm64", &feed).unwrap();
    assert!(arm.findings.is_empty());

    let err = scan_layout(dir.path(), "linux/s390x", &feed).unwrap_err();
    assert!(err.to_string().contains("linux/amd64, linux/arm64"), "{err}");
}

#[test]
fn tampered_layer_blob_fails_digest_check() {
    let benign = ca("Test Benign Root");
    let dir = tempfile::tempdir().unwrap();
    layout(dir.path(), &benign, &benign);
    let index: serde_json::Value = serde_json::from_slice(&std::fs::read(dir.path().join("index.json")).unwrap()).unwrap();
    let manifest_digest = index["manifests"][0]["digest"].as_str().unwrap().trim_start_matches("sha256:").to_string();
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.path().join("blobs/sha256").join(manifest_digest)).unwrap()).unwrap();
    let layer = manifest["layers"][0]["digest"].as_str().unwrap().trim_start_matches("sha256:").to_string();
    std::fs::write(dir.path().join("blobs/sha256").join(layer), b"not the original layer").unwrap();
    let err = scan_layout(dir.path(), "linux/amd64", &empty_feed()).unwrap_err();
    assert!(format!("{err:#}").contains("digest mismatch"), "{err:#}");
}
