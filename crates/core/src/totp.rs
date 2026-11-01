//! TOTP codes (RFC 6238), the six digits of "two-factor authentication".
//!
//! An item's `totp` field holds what the service showed when 2FA was set
//! up: either the bare secret in base32 (`JBSW Y3DP …`) or the
//! `otpauth://totp/…?secret=…` URI behind the QR code, which may also carry
//! the algorithm, the number of digits and the period. Defaults are the
//! ones nearly every service uses: SHA-1, 6 digits, 30 seconds.

use std::fmt;

use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TotpError {
    Base32,
    EmptySecret,
    Uri(String),
}

impl fmt::Display for TotpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Base32 => f.write_str("the TOTP secret is not valid base32"),
            Self::EmptySecret => f.write_str("the TOTP secret is empty"),
            Self::Uri(why) => write!(f, "not a usable otpauth URI: {why}"),
        }
    }
}

impl std::error::Error for TotpError {}

pub struct Totp {
    secret: Zeroizing<Vec<u8>>,
    algorithm: Algorithm,
    digits: u32,
    period: u64,
}

impl fmt::Debug for Totp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Totp")
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .field("period", &self.period)
            .finish_non_exhaustive()
    }
}

impl Totp {
    pub fn parse(text: &str) -> Result<Self, TotpError> {
        let text = text.trim();
        let Some(rest) = text
            .get(..10)
            .filter(|p| p.eq_ignore_ascii_case("otpauth://"))
            .map(|_| &text[10..])
        else {
            return Self::new(decode_base32(text)?, Algorithm::Sha1, 6, 30);
        };

        let (kind, rest) = rest.split_once('/').ok_or(uri("no type"))?;
        if !kind.eq_ignore_ascii_case("totp") {
            return Err(uri("only totp is supported (not hotp)"));
        }
        let query = rest
            .split_once('?')
            .map(|(_, q)| q)
            .ok_or(uri("no parameters"))?;
        let (mut secret, mut algorithm, mut digits, mut period) = (None, Algorithm::Sha1, 6, 30);
        for pair in query.split('&') {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            let value = Zeroizing::new(percent_decode(value)?);
            match key.to_ascii_lowercase().as_str() {
                "secret" => secret = Some(decode_base32(&value)?),
                "algorithm" => {
                    algorithm = match value.to_ascii_uppercase().as_str() {
                        "SHA1" => Algorithm::Sha1,
                        "SHA256" => Algorithm::Sha256,
                        "SHA512" => Algorithm::Sha512,
                        _ => return Err(uri("unknown algorithm")),
                    };
                }
                "digits" => digits = value.parse().map_err(|_| uri("bad digits"))?,
                "period" => period = value.parse().map_err(|_| uri("bad period"))?,
                _ => {} // issuer, image and other labels
            }
        }
        Self::new(secret.ok_or(uri("no secret"))?, algorithm, digits, period)
    }

    fn new(
        secret: Zeroizing<Vec<u8>>,
        algorithm: Algorithm,
        digits: u32,
        period: u64,
    ) -> Result<Self, TotpError> {
        if secret.is_empty() {
            return Err(TotpError::EmptySecret);
        }
        if !(6..=8).contains(&digits) {
            return Err(uri("digits must be 6 to 8"));
        }
        if !(1..=300).contains(&period) {
            return Err(uri("period must be 1 to 300 seconds"));
        }
        Ok(Self {
            secret,
            algorithm,
            digits,
            period,
        })
    }

    pub fn period(&self) -> u64 {
        self.period
    }

    /// Seconds until the code at `unix_time` stops being valid.
    pub fn remaining(&self, unix_time: u64) -> u64 {
        self.period - unix_time % self.period
    }

    /// The code at `unix_time` (seconds since the epoch), zero-padded.
    pub fn code_at(&self, unix_time: u64) -> Zeroizing<String> {
        let counter = (unix_time / self.period).to_be_bytes();
        macro_rules! hmac {
            ($digest:ty) => {{
                let mut mac = <Hmac<$digest> as KeyInit>::new_from_slice(&self.secret)
                    .expect("HMAC takes any key length");
                mac.update(&counter);
                mac.finalize().into_bytes().to_vec()
            }};
        }
        let mac = Zeroizing::new(match self.algorithm {
            Algorithm::Sha1 => hmac!(Sha1),
            Algorithm::Sha256 => hmac!(Sha256),
            Algorithm::Sha512 => hmac!(Sha512),
        });
        // RFC 4226 dynamic truncation.
        let offset = usize::from(mac[mac.len() - 1] & 0x0f);
        let value =
            u32::from_be_bytes(mac[offset..offset + 4].try_into().expect("4 bytes")) & 0x7fff_ffff;
        let code = value % 10u32.pow(self.digits);
        let width = usize::try_from(self.digits).expect("at most 8");
        Zeroizing::new(format!("{code:0width$}"))
    }
}

fn uri(why: &str) -> TotpError {
    TotpError::Uri(why.to_owned())
}

/// RFC 4648 base32, as services print it: any case, spaces and hyphens
/// between groups, `=` padding optional.
fn decode_base32(text: &str) -> Result<Zeroizing<Vec<u8>>, TotpError> {
    let mut out = Zeroizing::new(Vec::with_capacity(text.len() * 5 / 8));
    let (mut buffer, mut bits) = (0u32, 0u32);
    for c in text.chars().filter(|c| !matches!(c, ' ' | '-' | '=')) {
        let value = match c.to_ascii_uppercase() {
            c @ 'A'..='Z' => u32::from(c) - u32::from('A'),
            c @ '2'..='7' => u32::from(c) - u32::from('2') + 26,
            _ => return Err(TotpError::Base32),
        };
        buffer = (buffer << 5) | value;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((buffer >> bits) & 0xff).expect("masked"));
        }
    }
    if out.is_empty() {
        return Err(TotpError::EmptySecret);
    }
    Ok(out)
}

fn percent_decode(text: &str) -> Result<String, TotpError> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let hex = text.get(i + 1..i + 3).ok_or(uri("bad percent escape"))?;
                out.push(u8::from_str_radix(hex, 16).map_err(|_| uri("bad percent escape"))?);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).map_err(|_| uri("not UTF-8"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6238 appendix B; also recomputed by `tools/totp_reference.py`.
    #[test]
    fn rfc6238_vectors() {
        let seeds = [
            (Algorithm::Sha1, &b"12345678901234567890"[..]),
            (Algorithm::Sha256, b"12345678901234567890123456789012"),
            (
                Algorithm::Sha512,
                b"1234567890123456789012345678901234567890123456789012345678901234",
            ),
        ];
        let table: [(u64, [&str; 3]); 6] = [
            (59, ["94287082", "46119246", "90693936"]),
            (1_111_111_109, ["07081804", "68084774", "25091201"]),
            (1_111_111_111, ["14050471", "67062674", "99943326"]),
            (1_234_567_890, ["89005924", "91819424", "93441116"]),
            (2_000_000_000, ["69279037", "90698825", "38618901"]),
            (20_000_000_000, ["65353130", "77737706", "47863826"]),
        ];
        for (time, codes) in table {
            for ((algorithm, seed), expected) in seeds.iter().zip(codes) {
                let totp = Totp::new(Zeroizing::new(seed.to_vec()), *algorithm, 8, 30).unwrap();
                assert_eq!(*totp.code_at(time), expected, "{algorithm:?} at {time}");
            }
        }
    }

    #[test]
    fn bare_base32_secret_uses_the_defaults() {
        // "12345678901234567890" in base32, spaced and lowercase as some
        // services print it.
        let totp = Totp::parse("gezd gnbv gy3t qojq gezd gnbv gy3t qojq").unwrap();
        assert_eq!(*totp.secret, b"12345678901234567890");
        assert_eq!(
            (totp.algorithm, totp.digits, totp.period),
            (Algorithm::Sha1, 6, 30)
        );
        // The 6-digit code is the last 6 digits of the 8-digit one.
        assert_eq!(*totp.code_at(59), "287082");
        assert_eq!(totp.remaining(59), 1);
        assert_eq!(totp.remaining(60), 30);
    }

    #[test]
    fn otpauth_uri_parameters_are_honoured() {
        let totp = Totp::parse(
            "otpauth://totp/Example%20Co:eduardo%40example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA\
             &issuer=Example+Co&algorithm=SHA256&digits=8&period=30",
        )
        .unwrap();
        assert_eq!(totp.algorithm, Algorithm::Sha256);
        assert_eq!(*totp.code_at(59), "46119246");
    }

    #[test]
    fn bad_input_is_refused() {
        assert_eq!(Totp::parse("not base32 1!").unwrap_err(), TotpError::Base32);
        assert_eq!(Totp::parse("   ").unwrap_err(), TotpError::EmptySecret);
        for (text, why) in [
            ("otpauth://hotp/x?secret=GEZDGNBV&counter=1", "hotp"),
            ("otpauth://totp/x?issuer=a", "no secret"),
            ("otpauth://totp/x?secret=GEZDGNBV&digits=4", "digits"),
            (
                "otpauth://totp/x?secret=GEZDGNBV&algorithm=MD5",
                "algorithm",
            ),
            ("otpauth://totp/x?secret=GEZDGNBV&period=0", "period"),
            ("otpauth://totp/x", "no parameters"),
        ] {
            let error = Totp::parse(text).unwrap_err().to_string();
            assert!(error.contains(why), "{text}: {error}");
        }
    }

    #[test]
    fn debug_hides_the_secret() {
        let totp = Totp::parse("GEZDGNBVGY3TQOJQ").unwrap();
        assert!(!format!("{totp:?}").contains("secret:"));
    }
}
