//! End-to-end scans over synthetic artifacts. Every certificate here is a freshly generated
//! self-signed test certificate, except the built-in feed test, which uses the public eMudhra root.

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use flate2::{Compression, write::GzEncoder};
use globset::GlobSet;
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};
use std::io::{Cursor, Write};
use trustsweep::extract::parse_pem_blocks;
use trustsweep::feed::{BinaryName, Feed, FeedCert, Fix, MatchedBy, Matcher, OneCrlEntry, Role};
use trustsweep::report::{Report, Verdict};
use trustsweep::scan::Scanner;

struct Pki {
    root_key: KeyPair,
    root_pem: String,
    root_der: Vec<u8>,
    benign_pem: String,
    benign_der: Vec<u8>,
    revoked_pem: String,
    revoked_der: Vec<u8>,
}

fn ca_params(cn: &str) -> CertificateParams {
    let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.distinguished_name.push(DnType::CommonName, cn);
    p
}

fn pki() -> Pki {
    let root_key = KeyPair::generate().unwrap();
    let root = ca_params("Test Distrusted Root").self_signed(&root_key).unwrap();
    let benign_key = KeyPair::generate().unwrap();
    let benign = ca_params("Test Benign Root").self_signed(&benign_key).unwrap();
    let issuer = Issuer::new(ca_params("Test Distrusted Root"), &root_key);
    let inter_key = KeyPair::generate().unwrap();
    let revoked = ca_params("Test Revoked Intermediate").signed_by(&inter_key, &issuer).unwrap();
    Pki {
        root_pem: root.pem(),
        root_der: root.der().to_vec(),
        benign_pem: benign.pem(),
        benign_der: benign.der().to_vec(),
        revoked_pem: revoked.pem(),
        revoked_der: revoked.der().to_vec(),
        root_key,
    }
}

fn feed_cert(name: &str, role: Role, pem: &str) -> FeedCert {
    let c = &parse_pem_blocks(pem.as_bytes())[0];
    FeedCert {
        name: name.into(),
        role,
        sha256: c.sha256.clone(),
        spki_sha256: c.spki_sha256.clone(),
        pem: pem.into(),
    }
}

fn fix(eco: &str, name: &str, v: &str) -> Fix {
    Fix {
        ecosystem: eco.into(),
        name: name.into(),
        fixed: vec![v.into()],
        source: "test".into(),
    }
}

fn matcher(p: &Pki, onecrl: Vec<OneCrlEntry>) -> Matcher {
    Feed {
        id: "test".into(),
        generated_at: "test".into(),
        sources: vec![],
        certs: vec![
            feed_cert("Test Distrusted Root", Role::Root, &p.root_pem),
            feed_cert("Test Revoked Intermediate", Role::Revoked, &p.revoked_pem),
        ],
        onecrl,
        removed: vec![],
        fixes: vec![
            fix("pypi", "certifi", "2099.1.1"),
            fix("deb", "ca-certificates", "99990101"),
            fix("npm", "electron", "99.0.0"),
            fix("maven", "com.example:sdk", "9.9.9"),
            fix("java", "jdk", "99.0.1"),
        ],
        binaries: vec![BinaryName {
            file: "uv".into(),
            ecosystem: "generic".into(),
            name: "uv".into(),
        }],
    }
    .compile("test".into())
    .unwrap()
}

fn run(m: &Matcher, f: impl FnOnce(&mut Scanner)) -> Report {
    let mut s = Scanner::new(m, GlobSet::empty(), 1 << 30).unwrap();
    f(&mut s);
    Report::build(s)
}

fn zip_bytes(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
    for (name, data) in files {
        w.start_file(*name, zip::write::SimpleFileOptions::default()).unwrap();
        w.write_all(data).unwrap();
    }
    w.finish().unwrap().into_inner()
}

fn tar_bytes(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut b = tar::Builder::new(Vec::new());
    for (name, data) in files {
        let mut h = tar::Header::new_gnu();
        h.set_size(data.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        b.append_data(&mut h, name, *data).unwrap();
    }
    b.into_inner().unwrap()
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut e = GzEncoder::new(Vec::new(), Compression::fast());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

#[test]
fn pem_bundle_in_venv_is_attributed_to_certifi() {
    let p = pki();
    let m = matcher(&p, vec![]);
    let dir = tempfile::tempdir().unwrap();
    let site = dir.path().join("lib/python3.12/site-packages");
    std::fs::create_dir_all(site.join("certifi")).unwrap();
    std::fs::create_dir_all(site.join("certifi-2026.7.22.dist-info")).unwrap();
    std::fs::write(site.join("certifi/cacert.pem"), format!("{}{}", p.benign_pem, p.root_pem)).unwrap();
    std::fs::write(
        site.join("certifi-2026.7.22.dist-info/RECORD"),
        "certifi/__init__.py,sha256=x,1\ncertifi/cacert.pem,sha256=y,2\n",
    )
    .unwrap();
    let r = run(&m, |s| s.scan_path(dir.path()));
    assert_eq!(r.findings.len(), 1);
    let f = &r.findings[0];
    assert_eq!(f.verdict, Verdict::Trusts);
    assert_eq!(f.cert_count, 2);
    let o = f.owner.as_ref().unwrap();
    assert_eq!((o.ecosystem.as_str(), o.name.as_str(), o.version.as_deref()), ("pypi", "certifi", Some("2026.7.22")));
    assert_eq!(f.fix.as_ref().unwrap().fixed, vec!["2099.1.1"]);
    assert_eq!(r.exit_code(), 1);
}

#[test]
fn pem_inside_js_string_literal_is_found() {
    let p = pki();
    let m = matcher(&p, vec![]);
    let js = |pem: &str| format!("\"{}\"", pem.trim_end().replace('\n', "\\n\" +\n  \""));
    let src = format!("module.exports = [{}, {}];\n", js(&p.benign_pem), js(&p.root_pem));
    let dir = tempfile::tempdir().unwrap();
    let pkg = dir.path().join("node_modules/electron");
    std::fs::create_dir_all(pkg.join("dist")).unwrap();
    std::fs::write(pkg.join("package.json"), r#"{"name":"electron","version":"41.0.0"}"#).unwrap();
    std::fs::write(pkg.join("dist/roots.js"), src).unwrap();
    let r = run(&m, |s| s.scan_path(dir.path()));
    assert_eq!(r.findings.len(), 1, "{}", r.text(false));
    let o = r.findings[0].owner.as_ref().unwrap();
    assert_eq!((o.name.as_str(), o.version.as_deref()), ("electron", Some("41.0.0")));
    assert_eq!(r.findings[0].verdict, Verdict::Trusts);
}

#[test]
fn concatenated_der_in_binary_is_found() {
    let p = pki();
    let m = matcher(&p, vec![]);
    let mut bin = vec![0x7f, b'E', b'L', b'F', 0x30, 0x82, 0x01];
    bin.extend(std::iter::repeat_n(0xAA, 500));
    bin.extend(&p.benign_der);
    bin.extend(&p.root_der);
    bin.extend(std::iter::repeat_n(0x00, 64));
    let r = run(&m, |s| s.scan_bytes("/opt/tool/bin/bun", &bin, 0));
    assert_eq!(r.findings.len(), 1);
    assert_eq!(r.findings[0].matches[0].matched_by, MatchedBy::Sha256);
    assert_eq!(r.findings[0].cert_count, 2);
}

#[test]
fn bare_public_key_like_webpki_roots_is_found() {
    let p = pki();
    let m = matcher(&p, vec![]);
    let mut bin = b"\x00\x01rust binary\x00".to_vec();
    bin.extend(p.root_key.public_key_raw());
    bin.extend(b"\x00trailer");
    let r = run(&m, |s| s.scan_bytes("/home/u/.local/bin/uv", &bin, 0));
    assert_eq!(r.findings.len(), 1);
    let f = &r.findings[0];
    assert_eq!(f.matches[0].matched_by, MatchedBy::EmbeddedKey);
    assert_eq!(f.verdict, Verdict::Trusts);
    assert_eq!(f.owner.as_ref().unwrap().name, "uv");
}

#[test]
fn reissued_root_with_same_key_matches_by_spki() {
    let p = pki();
    let m = matcher(&p, vec![]);
    let mut params = ca_params("Test Distrusted Root");
    params.serial_number = Some(vec![0x42].into());
    let reissued = params.self_signed(&p.root_key).unwrap();
    let bundle = format!("{}{}", p.benign_pem, reissued.pem());
    let r = run(&m, |s| s.scan_bytes("/etc/ssl/cert.pem", bundle.as_bytes(), 0));
    assert_eq!(r.findings[0].matches[0].matched_by, MatchedBy::Spki);
}

#[test]
fn wheel_and_jar_members_are_scanned_and_attributed() {
    let p = pki();
    let m = matcher(&p, vec![]);
    let bundle = format!("{}{}", p.benign_pem, p.root_pem);
    let whl = zip_bytes(&[
        ("certifi/cacert.pem", bundle.as_bytes()),
        ("certifi-2026.7.22.dist-info/RECORD", b"certifi/cacert.pem,sha256=y,2\n"),
    ]);
    // JKS: magic, then DER certificates inside trusted-cert entries.
    let mut jks = vec![0xfe, 0xed, 0xfe, 0xed, 0, 0, 0, 2, 0, 0, 0, 2];
    jks.extend(&p.benign_der);
    jks.extend([0, 0, 0, 2, 0, 5]);
    jks.extend(&p.root_der);
    let jar = zip_bytes(&[
        ("META-INF/maven/com.example/sdk/pom.properties", b"groupId=com.example\nartifactId=sdk\nversion=1.2.3\n"),
        ("certs/truststore.jks", &jks),
    ]);
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("certifi-2026.7.22-py3-none-any.whl"), whl).unwrap();
    std::fs::write(dir.path().join("sdk-1.2.3.jar"), jar).unwrap();
    let r = run(&m, |s| s.scan_path(dir.path()));
    assert_eq!(r.stats.archives, 2);
    let by = |suffix: &str| r.findings.iter().find(|f| f.path.ends_with(suffix)).unwrap();
    let w = by(".whl!/certifi/cacert.pem").owner.as_ref().unwrap();
    assert_eq!((w.name.as_str(), w.version.as_deref()), ("certifi", Some("2026.7.22")));
    let j = by(".jar!/certs/truststore.jks");
    let o = j.owner.as_ref().unwrap();
    assert_eq!((o.name.as_str(), o.version.as_deref()), ("com.example:sdk", Some("1.2.3")));
    assert_eq!(j.fix.as_ref().unwrap().fixed, vec!["9.9.9"]);
}

#[test]
fn jdk_cacerts_uses_release_file() {
    let p = pki();
    let m = matcher(&p, vec![]);
    let mut cacerts = b"\xfe\xed\xfe\xed".to_vec();
    cacerts.extend(&p.benign_der);
    cacerts.extend(&p.root_der);
    let r = run(&m, |s| {
        s.scan_bytes("/opt/java/openjdk/release", b"JAVA_VERSION=\"21.0.5\"\n", 0);
        s.scan_bytes("/opt/java/openjdk/lib/security/cacerts", &cacerts, 0);
    });
    let o = r.findings[0].owner.as_ref().unwrap();
    assert_eq!((o.ecosystem.as_str(), o.version.as_deref()), ("java", Some("21.0.5")));
}

fn image_tarball(dir: &std::path::Path, layers: Vec<Vec<u8>>) -> std::path::PathBuf {
    let names: Vec<String> = (0..layers.len()).map(|i| format!("blobs/sha256/{i:064}")).collect();
    let manifest = serde_json::json!([{"Config": "config.json", "RepoTags": ["test:1"], "Layers": names}]).to_string();
    let mut files: Vec<(&str, &[u8])> = vec![("manifest.json", manifest.as_bytes())];
    for (n, l) in names.iter().zip(&layers) {
        files.push((n, l));
    }
    let path = dir.join("image.tar");
    std::fs::write(&path, tar_bytes(&files)).unwrap();
    path
}

#[test]
fn image_layers_attribute_to_dpkg_and_honour_whiteouts() {
    let p = pki();
    let m = matcher(&p, vec![]);
    let bad = format!("{}{}", p.benign_pem, p.root_pem);
    let status = "Package: ca-certificates\nStatus: install ok installed\nVersion: 20230311+deb12u1\n\n";
    let layer0 = tar_bytes(&[
        ("etc/ssl/certs/ca-certificates.crt", bad.as_bytes()),
        ("opt/app/bundle.pem", bad.as_bytes()),
        ("var/lib/dpkg/status", status.as_bytes()),
    ]);
    let dir = tempfile::tempdir().unwrap();

    let only_base = image_tarball(dir.path(), vec![layer0.clone()]);
    let r = run(&m, |s| s.scan_image(&only_base).unwrap());
    let f = r.findings.iter().find(|f| f.path == "/etc/ssl/certs/ca-certificates.crt").unwrap();
    let o = f.owner.as_ref().unwrap();
    assert_eq!((o.ecosystem.as_str(), o.name.as_str(), o.version.as_deref()), ("deb", "ca-certificates", Some("20230311+deb12u1")));
    assert_eq!(f.layer, Some(0));
    assert_eq!(r.exit_code(), 1);

    let clean = p.benign_pem.to_string();
    let layer1 = gzip(&tar_bytes(&[
        ("etc/ssl/certs/ca-certificates.crt", clean.as_bytes()),
        ("opt/app/.wh.bundle.pem", b""),
    ]));
    let fixed = image_tarball(dir.path(), vec![layer0, layer1]);
    let r = run(&m, |s| s.scan_image(&fixed).unwrap());
    assert_eq!(r.findings.len(), 2);
    assert!(r.findings.iter().all(|f| f.superseded), "{}", r.text(false));
    assert_eq!(r.exit_code(), 0);
}

#[test]
fn false_positive_controls() {
    let p = pki();
    let m = matcher(&p, vec![]);
    let r = run(&m, |s| {
        s.scan_bytes("/repo/tests/fixtures/root.pem", p.root_pem.as_bytes(), 0);
        let chain = format!("{}{}", p.revoked_pem, p.root_pem);
        s.scan_bytes("/repo/chain.pem", chain.as_bytes(), 0);
        s.scan_bytes("/repo/clean.pem", p.benign_pem.as_bytes(), 0);
    });
    assert_eq!(r.findings.len(), 2);
    assert!(r.findings.iter().all(|f| f.verdict == Verdict::Review));
    assert_eq!(r.exit_code(), 0);
}

#[test]
fn exclude_glob_skips_paths() {
    let p = pki();
    let m = matcher(&p, vec![]);
    let globs = globset::GlobSetBuilder::new()
        .add(globset::Glob::new("**/tests/**").unwrap())
        .build()
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("tests")).unwrap();
    std::fs::write(dir.path().join("tests/ca.pem"), format!("{}{}", p.benign_pem, p.root_pem)).unwrap();
    let mut s = Scanner::new(&m, globs, 1 << 30).unwrap();
    s.scan_path(dir.path());
    let r = Report::build(s);
    assert!(r.findings.is_empty());
    assert_eq!(r.stats.excluded, 1);
}

#[test]
fn onecrl_issuer_serial_entry_matches() {
    let p = pki();
    let c = &parse_pem_blocks(p.revoked_pem.as_bytes())[0];
    let entry = OneCrlEntry {
        subject: None,
        pub_key_hash: None,
        issuer: Some(B64.encode(&c.issuer_der)),
        serial: Some(B64.encode(&c.serial)),
    };
    let feed_only_onecrl = Feed {
        id: "t".into(),
        generated_at: "t".into(),
        sources: vec![],
        certs: vec![],
        onecrl: vec![entry],
        removed: vec![],
        fixes: vec![],
        binaries: vec![],
    }
    .compile("t".into())
    .unwrap();
    assert_eq!(feed_only_onecrl.match_cert(c).unwrap().1, MatchedBy::IssuerSerial);
    assert_eq!(feed_only_onecrl.targets[0].name, format!("serial {} issued by Test Distrusted Root", hex::encode(&c.serial)));
    let r = run(&feed_only_onecrl, |s| s.scan_bytes("/x/revoked.der", &p.revoked_der, 0));
    assert_eq!(r.findings[0].matches[0].role, Role::Revoked);
}

#[test]
fn builtin_feed_flags_public_emsign_root() {
    let (feed, _) = Feed::load(Some(std::path::Path::new("data/feed.json"))).unwrap();
    let m = feed.compile("builtin".into()).unwrap();
    let emsign = feed.certs.iter().find(|c| c.name == "emSign ECC Root CA - G3").unwrap();
    assert_eq!(emsign.sha256, "86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B");
    assert_eq!(feed.certs.iter().filter(|c| c.role == Role::Revoked).count(), 16);
    let aaa = feed.certs.iter().find(|c| c.name == "AAA Certificate Services").unwrap();
    let bundle = format!("{}\n{}\n", aaa.pem, emsign.pem);
    let r = run(&m, |s| s.scan_bytes("/usr/lib/python3/dist-packages/certifi/cacert.pem", bundle.as_bytes(), 0));
    assert_eq!(r.findings[0].verdict, Verdict::Trusts);
    assert_eq!(r.findings[0].matches.len(), 2);
}

#[test]
fn sarif_has_error_result() {
    let p = pki();
    let m = matcher(&p, vec![]);
    let bundle = format!("{}{}", p.benign_pem, p.root_pem);
    let r = run(&m, |s| s.scan_bytes("/etc/ssl/cert.pem", bundle.as_bytes(), 0));
    let v = r.sarif();
    assert_eq!(v["version"], "2.1.0");
    let res = &v["runs"][0]["results"][0];
    assert_eq!(res["level"], "error");
    assert_eq!(res["ruleId"], "trusts-revoked-ca");
    assert_eq!(res["locations"][0]["physicalLocation"]["region"]["byteLength"], r.findings[0].matches[0].len);
}

#[test]
fn js_joined_pem_keeps_base64_plus_at_line_start() {
    // The public feed certificates include one whose base64 has a line starting with `+`.
    let (feed, _) = Feed::load(Some(std::path::Path::new("data/feed.json"))).unwrap();
    for c in &feed.certs {
        let js = format!("\"{}\"", c.pem.trim_end().replace('\n', "\\n\" +\n  \""));
        let found = parse_pem_blocks(js.as_bytes());
        assert_eq!(found.len(), 1, "{}", c.name);
        assert_eq!(found[0].sha256, c.sha256);
    }
}

fn escaped(der: &[u8], octal: bool) -> String {
    der.iter()
        .map(|b| if octal { format!("\\{b:o}") } else { format!("\\x{b:02X}") })
        .collect()
}

#[test]
fn escaped_source_literals_are_found() {
    let p = pki();
    let m = matcher(&p, vec![]);
    // webpki-root-certs style Rust source, and a C header using octal escapes.
    let rust = format!(
        "pub const TLS_SERVER_ROOT_CERTS: &[CertificateDer<'static>] = &[\n  CertificateDer::from_slice(b\"{}\"),\n  CertificateDer::from_slice(b\"{}\"),\n];\n",
        escaped(&p.benign_der, false),
        escaped(&p.root_der, false)
    );
    let c = format!("static const char roots[] = \"{}\";\n", escaped(&p.root_der, true));
    let xxd: Vec<String> = p.root_der.iter().map(|b| format!("0x{b:02x}")).collect();
    let xxd = format!("unsigned char root_der[] = {{\n  {}\n}};\n", xxd.join(", "));
    let r = run(&m, |s| {
        s.scan_bytes("/v/webpki-root-certs-1.0.9/src/lib.rs", rust.as_bytes(), 0);
        s.scan_bytes("/v/roots.h", c.as_bytes(), 0);
        s.scan_bytes("/v/root_der.h", xxd.as_bytes(), 0);
    });
    assert!(r.findings.iter().any(|f| f.path.ends_with("root_der.h")));
    let lib = r.findings.iter().find(|f| f.path.ends_with("lib.rs")).unwrap();
    assert_eq!(lib.verdict, Verdict::Trusts);
    assert_eq!(lib.cert_count, 2);
    let h = r.findings.iter().find(|f| f.path.ends_with("roots.h")).unwrap();
    assert_eq!(h.matches[0].matched_by, MatchedBy::Sha256);
}

#[test]
fn distroless_status_d_and_rpm_paths_are_attributed() {
    let p = pki();
    let m = matcher(&p, vec![]);
    let bad = format!("{}{}", p.benign_pem, p.root_pem);
    let r = run(&m, |s| {
        s.scan_bytes(
            "/var/lib/dpkg/status.d/ca-certificates",
            b"Package: ca-certificates\nVersion: 20230311+deb12u1\nArchitecture: all\n",
            0,
        );
        s.scan_bytes("/var/lib/dpkg/status.d/ca-certificates.md5sums", b"0123  usr/share/doc/ca-certificates/copyright\n", 0);
        s.scan_bytes("/etc/ssl/certs/ca-certificates.crt", bad.as_bytes(), 0);
    });
    let o = r.findings[0].owner.as_ref().unwrap();
    assert_eq!((o.ecosystem.as_str(), o.name.as_str(), o.version.as_deref()), ("deb", "ca-certificates", Some("20230311+deb12u1")));

    let r = run(&m, |s| s.scan_bytes("/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", bad.as_bytes(), 0));
    let o = r.findings[0].owner.as_ref().unwrap();
    assert_eq!((o.ecosystem.as_str(), o.name.as_str()), ("rpm", "ca-certificates"));
}

#[test]
fn zstd_layers_are_scanned() {
    let p = pki();
    let m = matcher(&p, vec![]);
    let bad = format!("{}{}", p.benign_pem, p.root_pem);
    let layer = tar_bytes(&[("etc/ssl/cert.pem", bad.as_bytes())]);
    let zst = ruzstd::encoding::compress_to_vec(&layer[..], ruzstd::encoding::CompressionLevel::Fastest);
    assert_eq!(&zst[..4], &[0x28, 0xb5, 0x2f, 0xfd]);
    let dir = tempfile::tempdir().unwrap();
    let img = image_tarball(dir.path(), vec![zst]);
    let r = run(&m, |s| s.scan_image(&img).unwrap());
    assert_eq!(r.findings.len(), 1);
    assert_eq!(r.findings[0].path, "/etc/ssl/cert.pem");
}
