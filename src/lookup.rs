//! The self-hosted address lookup service that custom relays require, and the
//! secret that guards it.
//!
//! With custom relays nothing publishes to n0's infrastructure, so a peer
//! that changes its home relay would be unreachable to everyone who only
//! knows the old one. A self-hosted [pkarr] service (an `iroh-dns-server`)
//! is the publish path that puts the standard iroh failover back: servers
//! publish their relay URL there and clients resolve it. It is served behind
//! a capability URL — the whole service sits under `/<secret>/` and a reverse
//! proxy 404s everything else — so a [`LookupSecret`] is the credential and
//! the crate composes `<lookup_url>/<lookup_secret>/pkarr` itself.
//!
//! The design and the deployment recipe are in
//! <https://github.com/flexaccessdev/iroh-common-architecture>
//! (`relays-and-address-lookup.md` and `self-hosting.md`).
//!
//! [pkarr]: https://pkarr.org

use anyhow::{Context, Result, bail};
use std::fmt;
use std::str::FromStr;
use url::Url;

/// Prefix of every lookup secret. The `1` is the format version.
pub const LOOKUP_SECRET_PREFIX: &str = "lks1-";

/// Random bytes in a secret.
const SECRET_BYTES: usize = 20;
/// CRC-32 appended to the random bytes so a typo fails at config load.
const CHECKSUM_BYTES: usize = 4;
/// z-base-32 characters encoding `SECRET_BYTES + CHECKSUM_BYTES` bytes.
const ENCODED_LEN: usize = 39;

/// The z-base-32 alphabet: lowercase only, no padding, chosen for a value
/// that lives in a URL path and gets typed by hand.
const Z_BASE_32: &[u8; 32] = b"ybndrfg8ejkmcpqxot1uwisza345h769";

/// A validated lookup secret: `lks1-` followed by 39 z-base-32 characters
/// encoding 20 random bytes and their CRC-32.
///
/// Both sides of a connection carry the same secret. Parsing checks the
/// prefix, the alphabet (lowercase only — the token is never case-folded,
/// so a shouted copy is rejected rather than silently accepted) and the
/// checksum, so a mistyped secret fails when the configuration is loaded
/// instead of as a `404` from the lookup service at runtime.
#[derive(Clone, PartialEq, Eq)]
pub struct LookupSecret(String);

impl LookupSecret {
    /// A fresh random secret.
    pub fn generate() -> Self {
        let mut bytes = [0u8; SECRET_BYTES];
        getrandom::fill(&mut bytes).expect("operating system randomness");
        Self::from_bytes(&bytes)
    }

    fn from_bytes(bytes: &[u8; SECRET_BYTES]) -> Self {
        let mut payload = [0u8; SECRET_BYTES + CHECKSUM_BYTES];
        payload[..SECRET_BYTES].copy_from_slice(bytes);
        payload[SECRET_BYTES..].copy_from_slice(&crc32(bytes).to_be_bytes());
        let encoded = z_base_32_encode(&payload);
        debug_assert_eq!(encoded.len(), ENCODED_LEN);
        Self(format!("{LOOKUP_SECRET_PREFIX}{encoded}"))
    }

    /// Validate a configured secret. Surrounding whitespace is ignored;
    /// nothing else is normalized.
    pub fn parse(secret: &str) -> Result<Self> {
        let secret = secret.trim();
        let Some(encoded) = secret.strip_prefix(LOOKUP_SECRET_PREFIX) else {
            bail!(
                "lookup_secret must start with `{LOOKUP_SECRET_PREFIX}` (generate one with the program's generate-lookup-secret command)"
            );
        };
        if encoded.len() != ENCODED_LEN {
            bail!(
                "lookup_secret must be `{LOOKUP_SECRET_PREFIX}` followed by {ENCODED_LEN} characters, got {}",
                encoded.len()
            );
        }
        let payload = z_base_32_decode(encoded).context(
            "lookup_secret has an invalid character (only lowercase z-base-32 letters and digits are allowed)",
        )?;
        let (bytes, checksum) = payload.split_at(SECRET_BYTES);
        if checksum != crc32(bytes).to_be_bytes() {
            bail!("lookup_secret checksum does not match: the secret was mistyped or truncated");
        }
        Ok(Self(secret.to_string()))
    }

    /// The full token, prefix included.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for LookupSecret {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s)
    }
}

impl fmt::Display for LookupSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Redacted: the secret is a credential and never belongs in logs.
impl fmt::Debug for LookupSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LookupSecret(<redacted>)")
    }
}

/// Where the lookup service is and how to get in: the pair every program
/// configures as `lookup_url` and `lookup_secret`.
#[derive(Clone, PartialEq, Eq)]
pub struct LookupConfig {
    url: Url,
    secret: LookupSecret,
}

impl LookupConfig {
    /// Validate the configured pair.
    ///
    /// `url` is the scheme and host of the service only, e.g.
    /// `https://lookup.example.com`: a path, query, fragment, or credentials
    /// are rejected because the crate owns the layout beneath the host (see
    /// [`Self::pkarr_url`]).
    pub fn new(url: &str, secret: &str) -> Result<Self> {
        let url = url.trim();
        let parsed = Url::parse(url).with_context(|| format!("Invalid lookup_url: {url}"))?;
        if !matches!(parsed.scheme(), "http" | "https") {
            bail!("lookup_url must use http or https, got `{}`", parsed.scheme());
        }
        if parsed.host_str().is_none() {
            bail!("lookup_url has no host: {url}");
        }
        if !matches!(parsed.path(), "" | "/") {
            bail!(
                "lookup_url must not have a path (got `{}`): give only the scheme and host, the `/<lookup_secret>/pkarr` layout is added automatically",
                parsed.path()
            );
        }
        if parsed.query().is_some() || parsed.fragment().is_some() {
            bail!("lookup_url must not have a query or fragment: {url}");
        }
        if !parsed.username().is_empty() || parsed.password().is_some() {
            bail!("lookup_url must not carry credentials; the lookup_secret is the credential");
        }
        Ok(Self {
            url: parsed,
            secret: LookupSecret::parse(secret)?,
        })
    }

    /// The configured base URL (scheme and host).
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// The secret.
    pub fn secret(&self) -> &LookupSecret {
        &self.secret
    }

    /// The pkarr endpoint iroh publishes to and resolves from:
    /// `<lookup_url>/<lookup_secret>/pkarr`. iroh appends `/<endpoint id>`.
    pub fn pkarr_url(&self) -> Url {
        let mut url = self.url.clone();
        url.path_segments_mut()
            .expect("http(s) URLs have path segments")
            .pop_if_empty()
            .push(self.secret.as_str())
            .push("pkarr");
        url
    }

    /// The service as it may be named in logs: scheme and host, no secret.
    pub fn display_host(&self) -> String {
        match self.url.port() {
            Some(port) => format!(
                "{}://{}:{port}",
                self.url.scheme(),
                self.url.host_str().unwrap_or_default()
            ),
            None => format!(
                "{}://{}",
                self.url.scheme(),
                self.url.host_str().unwrap_or_default()
            ),
        }
    }
}

/// Redacted secret; the host is shown.
impl fmt::Debug for LookupConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LookupConfig")
            .field("url", &self.url.as_str())
            .field("secret", &self.secret)
            .finish()
    }
}

/// CRC-32 (IEEE 802.3, as in zip and PNG) of `data`.
fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// z-base-32, unpadded, most significant bit first.
fn z_base_32_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    let mut buffer: u32 = 0;
    let mut bits = 0u32;
    for &byte in bytes {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(Z_BASE_32[((buffer >> bits) & 0x1F) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(Z_BASE_32[((buffer << (5 - bits)) & 0x1F) as usize] as char);
    }
    out
}

/// Inverse of [`z_base_32_encode`]. Strict: unknown characters (uppercase
/// included) and non-zero padding bits are errors.
fn z_base_32_decode(text: &str) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() * 5 / 8);
    let mut buffer: u32 = 0;
    let mut bits = 0u32;
    for ch in text.bytes() {
        let value = Z_BASE_32
            .iter()
            .position(|&c| c == ch)
            .with_context(|| format!("invalid z-base-32 character `{}`", ch as char))?;
        buffer = (buffer << 5) | value as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xFF) as u8);
        }
    }
    if bits >= 5 || (buffer & ((1 << bits) - 1)) != 0 {
        bail!("invalid z-base-32 padding");
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_matches_the_ieee_check_value() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn z_base_32_round_trips_and_rejects_bad_input() {
        for len in 0..12 {
            let bytes: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
            let encoded = z_base_32_encode(&bytes);
            assert!(encoded.bytes().all(|c| Z_BASE_32.contains(&c)));
            assert_eq!(z_base_32_decode(&encoded).unwrap(), bytes);
        }
        // Known vector from the z-base-32 spec: 0xf0bf c7 -> "6n9hq".
        assert_eq!(z_base_32_encode(&[0xf0, 0xbf, 0xc7]), "6n9hq");
        assert!(z_base_32_decode("6N9HQ").is_err(), "uppercase is not folded");
        assert!(z_base_32_decode("l").is_err(), "l is not in the alphabet");
    }

    #[test]
    fn generated_secret_has_the_documented_shape_and_parses() {
        let secret = LookupSecret::generate();
        let text = secret.to_string();
        assert!(text.starts_with(LOOKUP_SECRET_PREFIX));
        assert_eq!(text.len(), LOOKUP_SECRET_PREFIX.len() + ENCODED_LEN);
        assert_eq!(text.to_lowercase(), text, "secret must be lowercase");
        assert_eq!(LookupSecret::parse(&text).unwrap(), secret);
        assert_eq!(format!("  {text}\n").parse::<LookupSecret>().unwrap(), secret);
        assert_ne!(LookupSecret::generate(), secret);
    }

    #[test]
    fn a_typo_fails_the_checksum() {
        let text = LookupSecret::generate().to_string();
        let mut chars: Vec<char> = text.chars().collect();
        let i = LOOKUP_SECRET_PREFIX.len() + 3;
        chars[i] = if chars[i] == 'y' { 'b' } else { 'y' };
        let typo: String = chars.into_iter().collect();
        let err = LookupSecret::parse(&typo).expect_err("typo must be rejected");
        assert!(err.to_string().contains("checksum"), "unexpected error: {err}");

        let truncated = &text[..text.len() - 1];
        let err = LookupSecret::parse(truncated).expect_err("truncation must be rejected");
        assert!(err.to_string().contains("39 characters"), "unexpected error: {err}");

        let err = LookupSecret::parse(&text.to_uppercase()).expect_err("uppercase must be rejected");
        assert!(err.to_string().contains("must start with"), "unexpected error: {err}");

        let shouted = format!("{LOOKUP_SECRET_PREFIX}{}", text[LOOKUP_SECRET_PREFIX.len()..].to_uppercase());
        let err = LookupSecret::parse(&shouted).expect_err("uppercase body must be rejected");
        assert!(err.to_string().contains("invalid character"), "unexpected error: {err}");

        let err = LookupSecret::parse("secret").expect_err("wrong prefix must be rejected");
        assert!(err.to_string().contains("must start with"), "unexpected error: {err}");
    }

    #[test]
    fn secret_debug_is_redacted() {
        let secret = LookupSecret::generate();
        let dbg = format!("{secret:?}");
        assert!(!dbg.contains(&secret.to_string()[10..]), "secret leaked: {dbg}");
        assert!(dbg.contains("<redacted>"));
    }

    #[test]
    fn lookup_url_is_scheme_and_host_only() {
        let secret = LookupSecret::generate().to_string();
        let cfg = LookupConfig::new("https://lookup.example.com", &secret).unwrap();
        assert_eq!(
            cfg.pkarr_url().as_str(),
            format!("https://lookup.example.com/{secret}/pkarr")
        );
        assert_eq!(cfg.display_host(), "https://lookup.example.com");

        let cfg = LookupConfig::new(" http://127.0.0.1:8053/ ", &secret).unwrap();
        assert_eq!(cfg.pkarr_url().as_str(), format!("http://127.0.0.1:8053/{secret}/pkarr"));
        assert_eq!(cfg.display_host(), "http://127.0.0.1:8053");

        for bad in [
            "https://lookup.example.com/pkarr",
            "https://lookup.example.com/?x=1",
            "https://lookup.example.com/#frag",
            "https://user:pw@lookup.example.com",
            "ftp://lookup.example.com",
            "lookup.example.com",
        ] {
            assert!(LookupConfig::new(bad, &secret).is_err(), "accepted {bad}");
        }
        assert!(LookupConfig::new("https://lookup.example.com", "lks1-nope").is_err());

        let dbg = format!("{cfg:?}");
        assert!(dbg.contains("127.0.0.1:8053") && dbg.contains("<redacted>"));
        assert!(!dbg.contains(&secret[10..]), "secret leaked: {dbg}");
    }
}
