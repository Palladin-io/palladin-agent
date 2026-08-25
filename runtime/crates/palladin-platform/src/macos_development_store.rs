use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use secrecy::{ExposeSecret, SecretSlice};
use security_framework::os::macos::keychain::SecKeychain;
use zeroize::Zeroizing;

use crate::palladin_root;
use crate::secure_store::{OsSecretStore, SecretSlot, SecretStore, StoreError};

const REQUEST_MAGIC: &[u8; 6] = b"PLDKC1";
const RESPONSE_MAGIC: &[u8; 6] = b"PLDKR1";
const HELPER_FILENAME: &str = "palladin-keychain-helper-v1";
const MAX_SECRET_BYTES: usize = 64 * 1024;
const REQUEST_HEADER_BYTES: usize = REQUEST_MAGIC.len() + 1 + 1 + 32 + 4;
const RESPONSE_HEADER_BYTES: usize = RESPONSE_MAGIC.len() + 1 + 4;

const OP_GET: u8 = 1;
const OP_SET: u8 = 2;
const OP_DELETE: u8 = 3;

const RESPONSE_FOUND: u8 = 0;
const RESPONSE_MISSING: u8 = 1;
const RESPONSE_OK: u8 = 2;

#[derive(Clone, Copy, Debug, Default)]
pub struct MacDevelopmentSecretStore;

impl SecretStore for MacDevelopmentSecretStore {
    fn get(&self, owner_id: &str, slot: SecretSlot) -> Result<Option<SecretSlice<u8>>, StoreError> {
        let mut response = invoke_helper(OP_GET, owner_id, slot, &[])?;
        match response.status {
            RESPONSE_FOUND => Ok(Some(response.take_secret()?.into())),
            RESPONSE_MISSING => Ok(None),
            _ => Err(StoreError::Unavailable),
        }
    }

    fn set(&self, owner_id: &str, slot: SecretSlot, secret: &[u8]) -> Result<(), StoreError> {
        if secret.is_empty() || secret.len() > MAX_SECRET_BYTES {
            return Err(StoreError::InvalidSecret);
        }
        let response = invoke_helper(OP_SET, owner_id, slot, secret)?;
        if response.status == RESPONSE_OK && response.body.is_empty() {
            Ok(())
        } else {
            Err(StoreError::Unavailable)
        }
    }

    fn delete(&self, owner_id: &str, slot: SecretSlot) -> Result<(), StoreError> {
        let response = invoke_helper(OP_DELETE, owner_id, slot, &[])?;
        if response.status == RESPONSE_OK && response.body.is_empty() {
            Ok(())
        } else {
            Err(StoreError::Unavailable)
        }
    }
}

struct HelperResponse {
    status: u8,
    body: Zeroizing<Vec<u8>>,
}

impl HelperResponse {
    fn take_secret(&mut self) -> Result<Vec<u8>, StoreError> {
        if self.body.is_empty() || self.body.len() > MAX_SECRET_BYTES {
            return Err(StoreError::Unavailable);
        }
        Ok(std::mem::take(&mut *self.body))
    }
}

fn invoke_helper(
    operation: u8,
    owner_id: &str,
    slot: SecretSlot,
    secret: &[u8],
) -> Result<HelperResponse, StoreError> {
    validate_request(operation, owner_id, secret)?;
    let helper = helper_path()?;
    validate_helper(&helper)?;

    let mut child = Command::new(&helper)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| StoreError::Unavailable)?;
    let mut stdin = child.stdin.take().ok_or(StoreError::Unavailable)?;
    write_request(&mut stdin, operation, owner_id, slot, secret)?;
    drop(stdin);

    let mut stdout = child.stdout.take().ok_or(StoreError::Unavailable)?;
    let mut response = Zeroizing::new(Vec::new());
    stdout
        .by_ref()
        .take((RESPONSE_HEADER_BYTES + MAX_SECRET_BYTES + 1) as u64)
        .read_to_end(&mut response)
        .map_err(|_| StoreError::Unavailable)?;
    drop(stdout);
    let status = child.wait().map_err(|_| StoreError::Unavailable)?;
    if !status.success() {
        return Err(StoreError::Unavailable);
    }
    parse_response(response)
}

fn helper_path() -> Result<PathBuf, StoreError> {
    palladin_root()
        .map(|root| root.join("development").join(HELPER_FILENAME))
        .map_err(|_| StoreError::Unavailable)
}

fn validate_helper(path: &std::path::Path) -> Result<(), StoreError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| StoreError::Unavailable)?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != unsafe_free_effective_uid()
        || metadata.mode() & 0o777 != 0o500
    {
        return Err(StoreError::Unavailable);
    }
    Ok(())
}

fn unsafe_free_effective_uid() -> u32 {
    nix::unistd::Uid::effective().as_raw()
}

fn validate_request(operation: u8, owner_id: &str, secret: &[u8]) -> Result<(), StoreError> {
    if !super::secure_store::valid_opaque_id(owner_id) {
        return Err(StoreError::InvalidOwner);
    }
    match operation {
        OP_GET | OP_DELETE if secret.is_empty() => Ok(()),
        OP_SET if !secret.is_empty() && secret.len() <= MAX_SECRET_BYTES => Ok(()),
        _ => Err(StoreError::InvalidSecret),
    }
}

fn write_request(
    output: &mut impl Write,
    operation: u8,
    owner_id: &str,
    slot: SecretSlot,
    secret: &[u8],
) -> Result<(), StoreError> {
    output
        .write_all(REQUEST_MAGIC)
        .and_then(|()| output.write_all(&[operation, slot_code(slot)]))
        .and_then(|()| output.write_all(owner_id.as_bytes()))
        .and_then(|()| output.write_all(&(secret.len() as u32).to_be_bytes()))
        .and_then(|()| output.write_all(secret))
        .and_then(|()| output.flush())
        .map_err(|_| StoreError::Unavailable)
}

fn parse_response(mut bytes: Zeroizing<Vec<u8>>) -> Result<HelperResponse, StoreError> {
    if bytes.len() < RESPONSE_HEADER_BYTES || &bytes[..RESPONSE_MAGIC.len()] != RESPONSE_MAGIC {
        return Err(StoreError::Unavailable);
    }
    let status = bytes[RESPONSE_MAGIC.len()];
    let length_offset = RESPONSE_MAGIC.len() + 1;
    let body_length = u32::from_be_bytes(
        bytes[length_offset..length_offset + 4]
            .try_into()
            .map_err(|_| StoreError::Unavailable)?,
    ) as usize;
    if body_length > MAX_SECRET_BYTES || bytes.len() != RESPONSE_HEADER_BYTES + body_length {
        return Err(StoreError::Unavailable);
    }
    let body = Zeroizing::new(bytes.split_off(RESPONSE_HEADER_BYTES));
    Ok(HelperResponse { status, body })
}

pub fn serve_development_keychain_helper() -> Result<(), StoreError> {
    // A missing or stale ACL must fail the operation. Development automation must
    // never summon a Keychain password dialog behind the operator's back.
    let _interaction_lock =
        SecKeychain::disable_user_interaction().map_err(|_| StoreError::Unavailable)?;
    let mut request = Zeroizing::new(Vec::new());
    std::io::stdin()
        .take((REQUEST_HEADER_BYTES + MAX_SECRET_BYTES + 1) as u64)
        .read_to_end(&mut request)
        .map_err(|_| StoreError::Unavailable)?;
    let parsed = parse_request(&request)?;
    let store = OsSecretStore;
    match parsed.operation {
        OP_GET => match store.get(parsed.owner_id, parsed.slot)? {
            Some(secret) => write_response(RESPONSE_FOUND, secret.expose_secret()),
            None => write_response(RESPONSE_MISSING, &[]),
        },
        OP_SET => {
            store.set(parsed.owner_id, parsed.slot, parsed.secret)?;
            write_response(RESPONSE_OK, &[])
        }
        OP_DELETE => {
            store.delete(parsed.owner_id, parsed.slot)?;
            write_response(RESPONSE_OK, &[])
        }
        _ => Err(StoreError::Unavailable),
    }
}

struct ParsedRequest<'a> {
    operation: u8,
    owner_id: &'a str,
    slot: SecretSlot,
    secret: &'a [u8],
}

fn parse_request(bytes: &[u8]) -> Result<ParsedRequest<'_>, StoreError> {
    if bytes.len() < REQUEST_HEADER_BYTES || &bytes[..REQUEST_MAGIC.len()] != REQUEST_MAGIC {
        return Err(StoreError::Unavailable);
    }
    let operation = bytes[REQUEST_MAGIC.len()];
    let slot = slot_from_code(bytes[REQUEST_MAGIC.len() + 1])?;
    let owner_offset = REQUEST_MAGIC.len() + 2;
    let owner_id = std::str::from_utf8(&bytes[owner_offset..owner_offset + 32])
        .map_err(|_| StoreError::InvalidOwner)?;
    let length_offset = owner_offset + 32;
    let secret_length = u32::from_be_bytes(
        bytes[length_offset..length_offset + 4]
            .try_into()
            .map_err(|_| StoreError::Unavailable)?,
    ) as usize;
    if secret_length > MAX_SECRET_BYTES || bytes.len() != REQUEST_HEADER_BYTES + secret_length {
        return Err(StoreError::Unavailable);
    }
    let secret = &bytes[REQUEST_HEADER_BYTES..];
    validate_request(operation, owner_id, secret)?;
    Ok(ParsedRequest {
        operation,
        owner_id,
        slot,
        secret,
    })
}

fn write_response(status: u8, body: &[u8]) -> Result<(), StoreError> {
    if body.len() > MAX_SECRET_BYTES {
        return Err(StoreError::Unavailable);
    }
    let mut output = std::io::stdout().lock();
    output
        .write_all(RESPONSE_MAGIC)
        .and_then(|()| output.write_all(&[status]))
        .and_then(|()| output.write_all(&(body.len() as u32).to_be_bytes()))
        .and_then(|()| output.write_all(body))
        .and_then(|()| output.flush())
        .map_err(|_| StoreError::Unavailable)
}

fn slot_code(slot: SecretSlot) -> u8 {
    match slot {
        SecretSlot::IntegrityTrustStateV1 => 1,
        SecretSlot::VersionPolicyTrustStateV1 => 2,
        SecretSlot::BrowserHostEd25519SecretKeyV1 => 3,
        SecretSlot::BrowserHostLifecycleTokenV1 => 4,
        SecretSlot::OrganizationApiKey => 5,
        SecretSlot::X25519PrivateKey => 6,
        SecretSlot::Ed25519SecretKey => 7,
        SecretSlot::LegacyOrganizationApiKeyV2 => 8,
        SecretSlot::LegacyX25519PrivateKeyV2 => 9,
        SecretSlot::LegacyEd25519SecretKeyV2 => 10,
    }
}

fn slot_from_code(code: u8) -> Result<SecretSlot, StoreError> {
    match code {
        1 => Ok(SecretSlot::IntegrityTrustStateV1),
        2 => Ok(SecretSlot::VersionPolicyTrustStateV1),
        3 => Ok(SecretSlot::BrowserHostEd25519SecretKeyV1),
        4 => Ok(SecretSlot::BrowserHostLifecycleTokenV1),
        5 => Ok(SecretSlot::OrganizationApiKey),
        6 => Ok(SecretSlot::X25519PrivateKey),
        7 => Ok(SecretSlot::Ed25519SecretKey),
        8 => Ok(SecretSlot::LegacyOrganizationApiKeyV2),
        9 => Ok(SecretSlot::LegacyX25519PrivateKeyV2),
        10 => Ok(SecretSlot::LegacyEd25519SecretKeyV2),
        _ => Err(StoreError::Unavailable),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_SECRET_BYTES, OP_DELETE, OP_GET, OP_SET, REQUEST_HEADER_BYTES, RESPONSE_FOUND,
        RESPONSE_MAGIC, SecretSlot, Zeroizing, parse_request, parse_response, write_request,
    };

    const OWNER: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn request_round_trip_keeps_secret_out_of_the_header() {
        let secret = b"sensitive-test-value";
        let mut request = Vec::new();
        write_request(
            &mut request,
            OP_SET,
            OWNER,
            SecretSlot::OrganizationApiKey,
            secret,
        )
        .expect("request");
        assert_eq!(&request[REQUEST_HEADER_BYTES..], secret);
        let parsed = parse_request(&request).expect("parsed");
        assert_eq!(parsed.operation, OP_SET);
        assert_eq!(parsed.owner_id, OWNER);
        assert_eq!(parsed.slot, SecretSlot::OrganizationApiKey);
        assert_eq!(parsed.secret, secret);
    }

    #[test]
    fn malformed_and_oversized_requests_fail_closed() {
        let mut get = Vec::new();
        write_request(&mut get, OP_GET, OWNER, SecretSlot::X25519PrivateKey, &[]).expect("get");
        get.push(1);
        assert!(parse_request(&get).is_err());

        let mut delete = Vec::new();
        write_request(
            &mut delete,
            OP_DELETE,
            OWNER,
            SecretSlot::Ed25519SecretKey,
            &[],
        )
        .expect("delete");
        delete[REQUEST_HEADER_BYTES - 4..REQUEST_HEADER_BYTES]
            .copy_from_slice(&((MAX_SECRET_BYTES + 1) as u32).to_be_bytes());
        assert!(parse_request(&delete).is_err());
    }

    #[test]
    fn response_parser_requires_an_exact_bounded_frame() {
        let body = b"secret";
        let mut response = RESPONSE_MAGIC.to_vec();
        response.push(RESPONSE_FOUND);
        response.extend_from_slice(&(body.len() as u32).to_be_bytes());
        response.extend_from_slice(body);
        let parsed = parse_response(Zeroizing::new(response)).expect("response");
        assert_eq!(parsed.status, RESPONSE_FOUND);
        assert_eq!(&*parsed.body, body);
    }
}
