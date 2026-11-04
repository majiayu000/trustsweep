//! Regression tests for the fixed-version table: recommendations must point at releases that
//! actually scan clean, and a release at or above its fix that still is not clean must not be
//! told to upgrade to itself.

use globset::GlobSet;
use std::path::Path;
use trustsweep::feed::{Feed, Matcher, Role};
use trustsweep::report::{Report, at_or_above};
use trustsweep::scan::Scanner;

fn builtin() -> Feed {
    Feed::load(Some(Path::new("data/feed.json"))).unwrap().0
}

fn fixed(feed: &Feed, eco: &str, name: &str) -> Vec<String> {
    feed.fixes.iter().find(|f| f.ecosystem == eco && f.name == name).unwrap().fixed.clone()
}

/// A bundle holding two public eMudhra-incident roots from the built-in feed.
fn bad_bundle(feed: &Feed) -> String {
    let pem = |n: &str| feed.certs.iter().find(|c| c.name == n).unwrap().pem.clone();
    format!("{}\n{}\n", pem("AAA Certificate Services"), pem("emSign ECC Root CA - G3"))
}

/// A venv where `dist`'s RECORD lists `file`, which holds `bundle`.
fn scan_venv(m: &Matcher, dist: &str, file: &str, bundle: &str) -> Report {
    let dir = tempfile::tempdir().unwrap();
    let site = dir.path().join("lib/python3.12/site-packages");
    let target = site.join(file);
    std::fs::create_dir_all(target.parent().unwrap()).unwrap();
    std::fs::write(&target, bundle).unwrap();
    std::fs::create_dir_all(site.join(format!("{dist}.dist-info"))).unwrap();
    std::fs::write(site.join(format!("{dist}.dist-info/RECORD")), format!("{file},sha256=x,1\n")).unwrap();
    let mut s = Scanner::new(m, GlobSet::empty(), 1 << 30).unwrap();
    s.scan_path(dir.path());
    Report::build(s)
}

#[test]
fn certifi_2026_10_19_is_not_a_fix() {
    // 2026.10.19 put emSign Root CA - C1 and emSign ECC Root CA - C3 back.
    let f = fixed(&builtin(), "pypi", "certifi");
    assert!(!f.contains(&"2026.10.19".to_string()), "{f:?}");
    assert_eq!(f, ["2026.10.23"]);
}

#[test]
fn pip_fix_is_the_release_that_vendors_a_clean_certifi() {
    // pip 26.2.2 vendors certifi 2026.10.19; 26.3 vendors 2026.10.23.
    assert_eq!(fixed(&builtin(), "pypi", "pip"), ["26.3"]);
}

#[test]
fn every_fix_entry_records_how_it_was_verified() {
    for f in &builtin().fixes {
        assert!(!f.verified.is_empty(), "{} {} has no verification note", f.ecosystem, f.name);
    }
}

#[test]
fn old_pip_is_told_to_upgrade_to_26_3() {
    let feed = builtin();
    let m = feed.compile("t".into()).unwrap();
    let r = scan_venv(&m, "pip-25.0.1", "pip/_vendor/certifi/cacert.pem", &bad_bundle(&feed));
    let f = &r.findings[0];
    assert_eq!(f.owner.as_ref().unwrap().name, "pip");
    assert!(!f.at_or_above_fix);
    assert_eq!(f.fix.as_ref().unwrap().fixed, ["26.3"]);
    assert!(r.text(false).contains("fix: upgrade to 26.3"));
}

#[test]
fn unclean_release_at_or_above_its_fix_is_not_told_to_upgrade_to_itself() {
    let feed = builtin();
    let m = feed.compile("t".into()).unwrap();
    for version in ["2026.10.23", "2026.11.1"] {
        let r = scan_venv(&m, &format!("certifi-{version}"), "certifi/cacert.pem", &bad_bundle(&feed));
        let f = &r.findings[0];
        assert!(f.at_or_above_fix, "{version}");
        let text = r.text(false);
        assert!(!text.contains("fix: upgrade to"), "{text}");
        assert!(text.contains("already at or above the listed fixed release"), "{text}");
        let sarif = r.sarif().to_string();
        assert!(!sarif.contains("upgrade to 2026.10.23"), "{sarif}");
    }
    // An older release still gets the normal recommendation.
    let r = scan_venv(&m, "certifi-2026.10.19", "certifi/cacert.pem", &bad_bundle(&feed));
    assert!(!r.findings[0].at_or_above_fix);
    assert!(r.text(false).contains("fix: upgrade to 2026.10.23"));
}

#[test]
fn at_or_above_compares_within_the_branch() {
    let node: Vec<String> = ["22.23.4", "24.22.1", "26.12.1"].map(String::from).to_vec();
    assert!(at_or_above("22.23.4", &node));
    assert!(at_or_above("24.30.0", &node));
    assert!(!at_or_above("22.15.0", &node));
    assert!(!at_or_above("24.0.0", &node), "a 24.x below 24.22.1 must not pass because of 22.23.4");
    assert!(!at_or_above("20250419~deb12u2", &["20250419~deb12u2".to_string()]), "unparsable versions never count");
}

#[test]
fn revoked_ca_present_only_as_a_bare_key_is_a_distrust_list() {
    // rustls-webpki compiles the compromised intermediates' keys into binaries as a blocklist.
    let feed = builtin();
    let m = feed.compile("t".into()).unwrap();
    let (key, _) = m
        .key_patterns
        .iter()
        .find(|(_, t)| m.targets[*t].role == Role::Revoked)
        .unwrap();
    let mut bin = b"\x00distrusted spki\x00".to_vec();
    bin.extend(key);
    let mut s = Scanner::new(&m, GlobSet::empty(), 1 << 30).unwrap();
    s.scan_bytes("/usr/local/bin/mise", &bin, 0);
    assert!(Report::build(s).findings.is_empty());
}
