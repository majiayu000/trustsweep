//! Find X.509 certificates in arbitrary bytes: PEM text, raw DER, or a bare embedded public key.

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use memchr::memmem;
use sha2::{Digest, Sha256};
use x509_parser::prelude::{FromDer, X509Certificate};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Encoding {
    Pem,
    Der,
    /// DER written as an escaped string literal in source code (`b"0\x82..."`).
    Escaped,
}

#[derive(Debug, Clone)]
pub struct ParsedCert {
    pub subject: String,
    pub sha256: String,
    pub sha256_bytes: [u8; 32],
    pub spki_sha256: String,
    pub spki_sha256_bytes: [u8; 32],
    pub issuer_der: Vec<u8>,
    pub serial: Vec<u8>,
    /// subjectPublicKey BIT STRING contents.
    pub public_key: Vec<u8>,
    pub encoding: Encoding,
    /// Byte range in the scanned buffer.
    pub offset: usize,
    pub len: usize,
}

fn sha(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// Parse exactly one DER certificate occupying all of `der`.
fn parse_der(der: &[u8], encoding: Encoding, offset: usize, len: usize) -> Option<ParsedCert> {
    let (rest, cert) = X509Certificate::from_der(der).ok()?;
    if !rest.is_empty() {
        return None;
    }
    let tbs = &cert.tbs_certificate;
    let subject = tbs
        .subject
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok().map(str::to_string))
        .unwrap_or_else(|| tbs.subject.to_string());
    let sha256_bytes = sha(der);
    let spki_sha256_bytes = sha(tbs.subject_pki.raw);
    Some(ParsedCert {
        subject,
        sha256: hex::encode_upper(sha256_bytes),
        sha256_bytes,
        spki_sha256: hex::encode_upper(spki_sha256_bytes),
        spki_sha256_bytes,
        issuer_der: tbs.issuer.as_raw().to_vec(),
        serial: tbs.raw_serial().to_vec(),
        public_key: tbs.subject_pki.subject_public_key.data.to_vec(),
        encoding,
        offset,
        len,
    })
}

const PEM_BEGINS: [&[u8]; 2] = [
    b"-----BEGIN CERTIFICATE-----",
    b"-----BEGIN TRUSTED CERTIFICATE-----",
];

fn is_quote(c: u8) -> bool {
    matches!(c, b'"' | b'\'' | b'`')
}

/// Base64 payload of a PEM body, also when it is split across C or JS string literals:
/// drops `\n`-style escapes and `" + "` joins, keeps the `+` that belongs to base64.
fn pem_base64(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len());
    let mut i = 0;
    while i < body.len() {
        let c = body[i];
        if c == b'\\' && matches!(body.get(i + 1), Some(b'n' | b'r' | b't')) {
            i += 2;
            continue;
        }
        if is_quote(c) {
            // `" + "` or `" "` joins two literals; anything else is a lone quote.
            let skip_ws = |mut j: usize| {
                while body.get(j).is_some_and(|b| b.is_ascii_whitespace()) {
                    j += 1;
                }
                j
            };
            let mut j = skip_ws(i + 1);
            if body.get(j) == Some(&b'+') {
                j = skip_ws(j + 1);
            }
            i = if body.get(j).copied().is_some_and(is_quote) { j + 1 } else { i + 1 };
            continue;
        }
        if c.is_ascii_alphanumeric() || c == b'+' || c == b'/' || c == b'=' {
            out.push(c);
        }
        i += 1;
    }
    out
}

/// PEM blocks, including ones inside C or JS string literals.
pub fn parse_pem_blocks(data: &[u8]) -> Vec<ParsedCert> {
    let mut out = Vec::new();
    for begin in PEM_BEGINS {
        let end_marker: &[u8] = if begin.len() == PEM_BEGINS[0].len() {
            b"-----END CERTIFICATE-----"
        } else {
            b"-----END TRUSTED CERTIFICATE-----"
        };
        for start in memmem::find_iter(data, begin) {
            let body_start = start + begin.len();
            let Some(end_rel) = memmem::find(&data[body_start..], end_marker) else {
                continue;
            };
            let body = &data[body_start..body_start + end_rel];
            let Ok(der) = B64.decode(pem_base64(body)) else { continue };
            // TRUSTED CERTIFICATE appends OpenSSL trust settings after the certificate.
            let der = match X509Certificate::from_der(&der) {
                Ok((rest, _)) => der[..der.len() - rest.len()].to_vec(),
                Err(_) => continue,
            };
            let len = body_start + end_rel + end_marker.len() - start;
            if let Some(c) = parse_der(&der, Encoding::Pem, start, len) {
                out.push(c);
            }
        }
    }
    out.sort_by_key(|c| c.offset);
    out
}

/// DER certificates anywhere in the buffer: JKS, unencrypted PKCS#12, concatenated DER, binaries.
pub fn parse_der_blobs(data: &[u8]) -> Vec<ParsedCert> {
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(rel) = memmem::find(&data[i..], &[0x30, 0x82]) {
        let at = i + rel;
        i = at + 1;
        let Some(h) = data.get(at..at + 8) else { break };
        let total = 4 + (((h[2] as usize) << 8) | h[3] as usize);
        // tbsCertificate SEQUENCE, then an explicit version [0] or a serial INTEGER.
        let first_field = match h[5] {
            0x82 => data.get(at + 8).copied(),
            0x81 => Some(h[7]),
            _ => None,
        };
        let tbs_ok = h[4] == 0x30 && matches!(first_field, Some(0xa0 | 0x02));
        if !tbs_ok || at + total > data.len() {
            continue;
        }
        if let Some(c) = parse_der(&data[at..at + total], Encoding::Der, at, total) {
            i = at + total;
            out.push(c);
        }
    }
    out
}

/// Decode a C/Rust/Go string literal body starting after its opening quote.
/// Returns the bytes and the offset of the closing quote.
fn unescape_literal(data: &[u8], mut i: usize) -> Option<(Vec<u8>, usize)> {
    const MAX_LITERAL: usize = 1 << 20;
    let start = i;
    let mut out = Vec::new();
    while i < data.len() && i - start < MAX_LITERAL {
        match data[i] {
            b'"' => return Some((out, i)),
            b'\\' => {
                let next = *data.get(i + 1)?;
                i += 2;
                match next {
                    b'x' => {
                        let hex = std::str::from_utf8(data.get(i..i + 2)?).ok()?;
                        out.push(u8::from_str_radix(hex, 16).ok()?);
                        i += 2;
                    }
                    b'0'..=b'7' => {
                        // C octal escape, up to three digits; also covers Rust `\0`.
                        let mut v = u32::from(next - b'0');
                        for _ in 0..2 {
                            match data.get(i) {
                                Some(d @ b'0'..=b'7') => {
                                    v = v * 8 + u32::from(d - b'0');
                                    i += 1;
                                }
                                _ => break,
                            }
                        }
                        out.push(u8::try_from(v).ok()?);
                    }
                    b'n' => out.push(b'\n'),
                    b'r' => out.push(b'\r'),
                    b't' => out.push(b'\t'),
                    b'\n' => {
                        // Rust line continuation skips the following whitespace.
                        while data.get(i).is_some_and(|b| b.is_ascii_whitespace()) {
                            i += 1;
                        }
                    }
                    other => out.push(other),
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    None
}

/// Certificates written as escaped string literals, as in webpki-root-certs or generated C headers.
pub fn parse_escaped_literals(data: &[u8]) -> Vec<ParsedCert> {
    let mut out = Vec::new();
    // A certificate starts with SEQUENCE 0x30 0x82, escaped as `0\x82`, `\x30\x82` or octal `\60\202`.
    for prefix in [&b"\"0\\x82"[..], b"\"\\x30\\x82", b"\"\\60\\202", b"\"\\060\\202"] {
        let mut i = 0;
        while let Some(rel) = memmem::find(&data[i..], prefix) {
            let quote = i + rel;
            i = quote + 1;
            let Some((bytes, end)) = unescape_literal(data, quote + 1) else {
                continue;
            };
            for mut c in parse_der_blobs(&bytes) {
                c.encoding = Encoding::Escaped;
                c.offset = quote;
                c.len = end + 1 - quote;
                out.push(c);
            }
            i = end + 1;
        }
    }
    out
}

/// Certificates written as C byte arrays (`{0x30, 0x82, ...}`, as `xxd -i` emits).
pub fn parse_hex_arrays(data: &[u8]) -> Vec<ParsedCert> {
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(rel) = memmem::find(&data[i..], b"0x30,") {
        let start = i + rel;
        let mut bytes = Vec::new();
        let mut j = start;
        // Tokens are `0xHH` separated by commas and whitespace.
        while let Some(tok) = data.get(j..j + 4) {
            let hex = match (tok[0], tok[1]) {
                (b'0', b'x' | b'X') => std::str::from_utf8(&tok[2..]).ok().and_then(|h| u8::from_str_radix(h, 16).ok()),
                _ => None,
            };
            let Some(b) = hex else { break };
            bytes.push(b);
            j += 4;
            while data.get(j).is_some_and(|c| *c == b',' || c.is_ascii_whitespace()) {
                j += 1;
            }
        }
        i = if j > start { j } else { start + 1 };
        if bytes.get(1) != Some(&0x82) {
            continue;
        }
        for mut c in parse_der_blobs(&bytes) {
            c.encoding = Encoding::Escaped;
            c.offset = start;
            c.len = j - start;
            out.push(c);
        }
    }
    out
}

/// All certificates in a buffer: PEM, DER and escaped source literals.
pub fn find_certs(data: &[u8]) -> Vec<ParsedCert> {
    let mut certs = parse_pem_blocks(data);
    certs.extend(parse_der_blobs(data));
    certs.extend(parse_escaped_literals(data));
    certs.extend(parse_hex_arrays(data));
    certs
}
