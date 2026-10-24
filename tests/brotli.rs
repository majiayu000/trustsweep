//! brotlisweep on synthetic binary fragments: only the decoder error-code strings and version
//! strings are planted, no real decoder code.

use globset::GlobSet;
use trustsweep::brotli::{Rules, Status, compare, fat_slices};
use trustsweep::brotli_report::BrotliReport;
use trustsweep::feed::{BinaryName, Feed, Matcher};
use trustsweep::scan::Scanner;

const CONTROL: &[u8] = b"\0_ERROR_FORMAT_EXUBERANT_NIBBLE\0";
const MARKER: &[u8] = b"\0_ERROR_FORMAT_BLOCK_SWITCH\0";

fn matcher() -> Matcher {
    Feed {
        id: "t".into(),
        generated_at: "t".into(),
        sources: vec![],
        certs: vec![],
        onecrl: vec![],
        removed: vec![],
        fixes: vec![],
        binaries: vec![BinaryName {
            file: "bun".into(),
            ecosystem: "generic".into(),
            name: "bun".into(),
        }],
    }
    .compile("t".into())
    .unwrap()
}

fn blob(parts: &[&[u8]]) -> Vec<u8> {
    let mut v = b"\x7fELF padding \x00\x01\x02".to_vec();
    for p in parts {
        v.extend_from_slice(p);
        v.extend_from_slice(b"\x00junk\x00");
    }
    v
}

fn run(f: impl FnOnce(&mut Scanner)) -> BrotliReport {
    let rules = Rules::builtin().unwrap();
    let m = matcher();
    let mut s = Scanner::new(&m, GlobSet::empty(), 1 << 30).unwrap().with_brotli(&rules);
    f(&mut s);
    BrotliReport::build(s, &rules)
}

/// A universal Mach-O header followed by the given slices (cputype, bytes), each 4 KiB aligned.
fn fat(slices: &[(u32, Vec<u8>)]) -> Vec<u8> {
    let mut offsets = Vec::new();
    let mut end = 4096usize;
    for (_, data) in slices {
        offsets.push(end);
        end = (end + data.len()).next_multiple_of(4096);
    }
    let mut out = Vec::new();
    out.extend(0xcafe_babe_u32.to_be_bytes());
    out.extend((slices.len() as u32).to_be_bytes());
    for ((cpu, data), off) in slices.iter().zip(&offsets) {
        for word in [*cpu, 0, *off as u32, data.len() as u32, 12] {
            out.extend(word.to_be_bytes());
        }
    }
    for ((_, data), off) in slices.iter().zip(&offsets) {
        out.resize(*off, 0);
        out.extend(data);
    }
    out
}

#[test]
fn old_bun_without_marker_is_unfixed() {
    let r = run(|s| s.scan_bytes("/home/u/.bun/bin/bun", &blob(&[CONTROL, b"bun-v1.3.14\0"]), 0));
    let f = &r.findings[0];
    assert_eq!(f.status, Status::Unfixed);
    let v = f.slices[0].version.as_ref().unwrap();
    assert_eq!((v.product.as_str(), v.version.as_str(), v.fixed_in.as_deref()), ("bun", "1.3.14", Some("1.4.4")));
    assert_eq!(f.owner.as_ref().unwrap().name, "bun");
    assert_eq!(r.exit_code(), 1);
}

#[test]
fn marker_means_fixed_even_for_an_old_version_string() {
    let r = run(|s| s.scan_bytes("/x/app", &blob(&[CONTROL, MARKER, b"bun-v1.3.14\0"]), 0));
    assert_eq!(r.findings[0].status, Status::Fixed);
    assert_eq!(r.exit_code(), 0);
}

#[test]
fn missing_marker_without_version_is_unknown_not_unfixed() {
    let r = run(|s| s.scan_bytes("/x/libsomething.dylib", &blob(&[CONTROL]), 0));
    assert_eq!(r.findings[0].status, Status::Unknown);
    assert_eq!(r.exit_code(), 0);
    let sarif = r.sarif();
    assert_eq!(sarif["runs"][0]["results"][0]["level"], "warning");
}

#[test]
fn fixed_version_without_marker_is_unknown() {
    let r = run(|s| s.scan_bytes("/x/node", &blob(&[CONTROL, b"nodejs.org/download/release/v24.22.1/"]), 0));
    assert_eq!(r.findings[0].status, Status::Unknown);
}

#[test]
fn electron_claim_takes_precedence_over_its_node_string() {
    let data = blob(&[CONTROL, b"Electron/39.2.7 Chrome", b"nodejs.org/download/release/v22.1.0/"]);
    let r = run(|s| s.scan_bytes("/Applications/A.app/Contents/Frameworks/Electron Framework", &data, 0));
    let f = &r.findings[0];
    assert_eq!(f.slices[0].version.as_ref().unwrap().product, "electron");
    assert_eq!(f.status, Status::Unknown, "no Electron advisory, so no unfixed verdict");
}

#[test]
fn files_without_decoder_strings_are_ignored() {
    let r = run(|s| s.scan_bytes("/x/other", &blob(&[b"bun-v1.0.0"]), 0));
    assert!(r.findings.is_empty());
}

#[test]
fn universal_macho_slices_are_judged_separately() {
    let arm = blob(&[CONTROL, MARKER]);
    let x86 = blob(&[CONTROL, b"bun-v1.2.0\0"]);
    let data = fat(&[(0x0100_000c, arm), (0x0100_0007, x86)]);
    let slices = fat_slices(&data).unwrap();
    assert_eq!(slices.iter().map(|s| s.0.as_str()).collect::<Vec<_>>(), ["arm64", "x86_64"]);
    let r = run(|s| s.scan_bytes("/Applications/T.app/Contents/MacOS/T", &data, 0));
    let f = &r.findings[0];
    let st: Vec<Status> = f.slices.iter().map(|s| s.status).collect();
    assert_eq!(st, [Status::Fixed, Status::Unfixed]);
    assert_eq!(f.status, Status::Unfixed);
}

#[test]
fn java_class_magic_is_not_a_fat_binary() {
    let mut class = vec![0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x41];
    class.extend(blob(&[CONTROL]));
    assert!(fat_slices(&class).is_none());
}

#[test]
fn pe_files_are_scanned_by_content() {
    let mut pe = b"MZ\x90\x00 This program cannot be run in DOS mode.\0PE\0\0".to_vec();
    pe.extend(blob(&[CONTROL, MARKER]));
    let r = run(|s| s.scan_bytes("C:/Program Files/App/app.exe", &pe, 0));
    assert_eq!(r.findings[0].status, Status::Fixed);
}

#[test]
fn python_brotli_version_and_http_clients() {
    let dir = tempfile::tempdir().unwrap();
    let site = dir.path().join("lib/python3.12/site-packages");
    let record = |name: &str, body: &str| {
        std::fs::create_dir_all(site.join(name)).unwrap();
        std::fs::write(site.join(name).join("RECORD"), body).unwrap();
    };
    record("Brotli-1.1.0.dist-info", "_brotli.cpython-312-darwin.so,sha256=x,1\nbrotli.py,sha256=y,2\n");
    record("urllib3-2.7.0.dist-info", "urllib3/__init__.py,,\n");
    record("requests-2.32.5.dist-info", "requests/__init__.py,,\n");
    record("rich-13.0.0.dist-info", "rich/__init__.py,,\n");
    std::fs::write(site.join("_brotli.cpython-312-darwin.so"), blob(&[CONTROL])).unwrap();
    let r = run(|s| s.scan_path(dir.path()));
    let f = &r.findings[0];
    assert_eq!(f.status, Status::Unfixed);
    assert_eq!(f.owner.as_ref().unwrap().name, "Brotli");
    assert_eq!(f.http_clients, vec!["requests 2.32.5", "urllib3 2.7.0"]);
    assert!(r.text().contains("Accept-Encoding: br"));
}

#[test]
fn version_comparison() {
    use std::cmp::Ordering::*;
    assert_eq!(compare("1.2.0", "1.2.1"), Some(Less));
    assert_eq!(compare("1.2.1.0", "1.2.1.0"), Some(Equal));
    assert_eq!(compare("22.15.0", "22.23.4"), Some(Less));
    assert_eq!(compare("1.4.4-canary", "1.4.4"), None);
}

#[test]
fn most_frequent_product_version_wins() {
    let data = blob(&[CONTROL, b"Deno/0.81.0", b"Deno/2.9.7", b"Deno/2.9.7", b"nodejs.org/download/release/v21.2.0/"]);
    let r = run(|s| s.scan_bytes("/opt/homebrew/bin/deno", &data, 0));
    let v = r.findings[0].slices[0].version.as_ref().unwrap();
    assert_eq!((v.product.as_str(), v.version.as_str()), ("deno", "2.9.7"));
    assert_eq!(r.findings[0].status, Status::Unknown);
}
