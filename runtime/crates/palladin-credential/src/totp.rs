use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac, digest::KeyInit};
use secrecy::{ExposeSecret, SecretString};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use thiserror::Error;
use zeroize::Zeroizing;

const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const DEFAULT_DIGITS: u32 = 6;
const DEFAULT_PERIOD: u64 = 30;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum TotpAlgorithm {
    #[default]
    Sha1,
    Sha256,
    Sha512,
}

pub struct TotpParams {
    pub secret: SecretString,
    pub algorithm: TotpAlgorithm,
    pub digits: u32,
    pub period: u64,
}

impl TotpParams {
    #[must_use]
    pub fn new(secret: String) -> Self {
        Self {
            secret: secret.into(),
            algorithm: TotpAlgorithm::default(),
            digits: DEFAULT_DIGITS,
            period: DEFAULT_PERIOD,
        }
    }
}

impl std::fmt::Debug for TotpParams {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TotpParams")
            .field("secret", &"[REDACTED]")
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .field("period", &self.period)
            .finish()
    }
}

pub struct TotpCode {
    pub code: SecretString,
    pub expires_in: u64,
}

impl std::fmt::Debug for TotpCode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TotpCode")
            .field("code", &"[REDACTED]")
            .field("expires_in", &self.expires_in)
            .finish()
    }
}

pub fn generate_totp(params: &TotpParams) -> Result<TotpCode, TotpError> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| TotpError::Clock)?
        .as_secs();
    generate_totp_at(params, seconds)
}

pub fn generate_totp_at(params: &TotpParams, unix_seconds: u64) -> Result<TotpCode, TotpError> {
    if !(6..=8).contains(&params.digits) {
        return Err(TotpError::InvalidDigits);
    }
    if params.period == 0 {
        return Err(TotpError::InvalidPeriod);
    }
    let key = base32_decode(params.secret.expose_secret())?;
    if key.is_empty() {
        return Err(TotpError::InvalidSecret);
    }
    let counter = unix_seconds / params.period;
    let digest = match params.algorithm {
        TotpAlgorithm::Sha1 => hmac::<Hmac<Sha1>>(&key, counter)?,
        TotpAlgorithm::Sha256 => hmac::<Hmac<Sha256>>(&key, counter)?,
        TotpAlgorithm::Sha512 => hmac::<Hmac<Sha512>>(&key, counter)?,
    };
    let offset = usize::from(digest[digest.len() - 1] & 0x0f);
    let binary = (u32::from(digest[offset] & 0x7f) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3]);
    let modulus = 10_u64.pow(params.digits);
    let code = format!(
        "{:0width$}",
        u64::from(binary) % modulus,
        width = params.digits as usize
    );
    Ok(TotpCode {
        code: code.into(),
        expires_in: params.period - (unix_seconds % params.period),
    })
}

fn hmac<M>(key: &[u8], counter: u64) -> Result<Zeroizing<Vec<u8>>, TotpError>
where
    M: Mac + KeyInit,
{
    let mut mac = <M as KeyInit>::new_from_slice(key).map_err(|_| TotpError::InvalidSecret)?;
    mac.update(&counter.to_be_bytes());
    Ok(Zeroizing::new(mac.finalize().into_bytes().to_vec()))
}

pub fn base32_decode(input: &str) -> Result<Zeroizing<Vec<u8>>, TotpError> {
    let mut output = Zeroizing::new(Vec::new());
    let mut bits = 0_u32;
    let mut value = 0_u32;
    for byte in input.bytes() {
        if byte.is_ascii_whitespace() || byte == b'=' {
            continue;
        }
        let upper = byte.to_ascii_uppercase();
        let index = BASE32_ALPHABET
            .iter()
            .position(|candidate| *candidate == upper)
            .ok_or(TotpError::InvalidSecret)? as u32;
        value = (value << 5) | index;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            output.push(((value >> bits) & 0xff) as u8);
        }
    }
    Ok(output)
}

#[cfg(test)]
fn base32_encode(bytes: &[u8]) -> String {
    let mut output = String::new();
    let mut bits = 0_u32;
    let mut value = 0_u32;
    for byte in bytes {
        value = (value << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            output.push(char::from(
                BASE32_ALPHABET[((value >> bits) & 0x1f) as usize],
            ));
        }
    }
    if bits > 0 {
        output.push(char::from(
            BASE32_ALPHABET[((value << (5 - bits)) & 0x1f) as usize],
        ));
    }
    output
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum TotpError {
    #[error("TOTP digit count must be between 6 and 8")]
    InvalidDigits,
    #[error("TOTP period must be greater than zero")]
    InvalidPeriod,
    #[error("TOTP secret has an invalid base32 encoding")]
    InvalidSecret,
    #[error("system clock is invalid")]
    Clock,
}

#[cfg(test)]
mod tests {
    use secrecy::ExposeSecret;

    use super::{
        TotpAlgorithm, TotpError, TotpParams, base32_decode, base32_encode, generate_totp_at,
    };

    #[test]
    fn matches_rfc_6238_vectors_for_every_supported_algorithm() {
        let cases = [
            (
                TotpAlgorithm::Sha1,
                b"12345678901234567890".as_slice(),
                "94287082",
            ),
            (
                TotpAlgorithm::Sha256,
                b"12345678901234567890123456789012".as_slice(),
                "46119246",
            ),
            (
                TotpAlgorithm::Sha512,
                b"1234567890123456789012345678901234567890123456789012345678901234".as_slice(),
                "90693936",
            ),
        ];
        for (algorithm, seed, expected) in cases {
            let mut params = TotpParams::new(base32_encode(seed));
            params.algorithm = algorithm;
            params.digits = 8;
            assert!(
                generate_totp_at(&params, 59)
                    .expect("TOTP")
                    .code
                    .expose_secret()
                    == expected,
                "RFC TOTP code diverged"
            );
        }
    }

    #[test]
    fn defaults_and_window_match_the_typescript_contract() {
        let params = TotpParams::new(base32_encode(b"12345678901234567890"));
        let result = generate_totp_at(&params, 59).expect("TOTP");
        assert!(
            result.code.expose_secret() == "287082",
            "default TOTP code diverged"
        );
        assert_eq!(result.expires_in, 1);
        assert_eq!(
            generate_totp_at(&params, 30).expect("boundary").expires_in,
            30
        );
    }

    #[test]
    fn digit_count_is_limited_to_the_frozen_contract_range() {
        let secret = base32_encode(b"12345678901234567890");

        for digits in [6, 8] {
            let mut params = TotpParams::new(secret.clone());
            params.digits = digits;
            let code = generate_totp_at(&params, 59).expect("supported digit count");
            assert_eq!(code.code.expose_secret().len(), digits as usize);
        }

        for digits in [5, 9] {
            let mut params = TotpParams::new(secret.clone());
            params.digits = digits;
            assert_eq!(
                generate_totp_at(&params, 59).expect_err("unsupported digit count"),
                TotpError::InvalidDigits
            );
        }
    }

    #[test]
    fn base32_is_case_space_and_padding_tolerant_without_leaking_input_in_errors() {
        let canonical = base32_decode("JBSWY3DPEHPK3PXP").expect("canonical");
        let decorated = base32_decode("jbsw y3dp ehpk 3pxp====").expect("decorated");
        assert_eq!(canonical.as_slice(), decorated.as_slice());
        assert_eq!(
            base32_decode("!!!!").expect_err("invalid"),
            TotpError::InvalidSecret
        );
        let debug = format!("{:?}", TotpParams::new("private-seed".to_owned()));
        let leaked = debug.contains("private-seed");
        assert!(!leaked, "TOTP debug output was not redacted");
    }
}
