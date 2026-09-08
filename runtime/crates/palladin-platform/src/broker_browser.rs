use subtle::ConstantTimeEq;
use thiserror::Error;

pub const BROKER_BROWSER_OPEN_ENV: &str = "PALLADIN_BROKER_BROWSER_OPEN_V1";
pub const BROKER_BROWSER_OPEN_PREFIX: &str = "PALLADIN_BROKER_BROWSER_OPEN_V1:";
const MAX_APPROVAL_URL_BYTES: usize = 512;
pub const BROKER_BROWSER_OPEN_BINDING_BYTES: usize = 32;
pub const MAX_BROKER_BROWSER_CONTROL_LINE_BYTES: usize = BROKER_BROWSER_OPEN_PREFIX.len()
    + (BROKER_BROWSER_OPEN_BINDING_BYTES * 2)
    + 1
    + MAX_APPROVAL_URL_BYTES
    + 1;

#[derive(Debug, Error, Eq, PartialEq)]
pub enum BrokerBrowserError {
    #[error("the broker browser-open request is invalid")]
    InvalidRequest,
}

pub fn generate_broker_browser_open_binding() -> Result<String, BrokerBrowserError> {
    let mut random = [0_u8; BROKER_BROWSER_OPEN_BINDING_BYTES];
    getrandom::fill(&mut random).map_err(|_| BrokerBrowserError::InvalidRequest)?;
    Ok(random.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn validate_binding(binding: &str) -> Result<(), BrokerBrowserError> {
    if binding.len() == BROKER_BROWSER_OPEN_BINDING_BYTES * 2
        && binding
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        Ok(())
    } else {
        Err(BrokerBrowserError::InvalidRequest)
    }
}

pub fn encode_broker_browser_open_request(
    binding: &str,
    url: &str,
) -> Result<String, BrokerBrowserError> {
    validate_binding(binding)?;
    validate_broker_browser_open_url(url)?;
    Ok(format!("{BROKER_BROWSER_OPEN_PREFIX}{binding}:{url}\n"))
}

pub fn decode_broker_browser_open_request(
    line: &[u8],
    expected_binding: &str,
) -> Result<Option<String>, BrokerBrowserError> {
    validate_binding(expected_binding)?;
    if !line.starts_with(BROKER_BROWSER_OPEN_PREFIX.as_bytes()) {
        return Ok(None);
    }
    let line = line
        .strip_suffix(b"\n")
        .ok_or(BrokerBrowserError::InvalidRequest)?;
    let body = &line[BROKER_BROWSER_OPEN_PREFIX.len()..];
    let separator = body
        .iter()
        .position(|byte| *byte == b':')
        .ok_or(BrokerBrowserError::InvalidRequest)?;
    let binding =
        std::str::from_utf8(&body[..separator]).map_err(|_| BrokerBrowserError::InvalidRequest)?;
    validate_binding(binding)?;
    if binding
        .as_bytes()
        .ct_eq(expected_binding.as_bytes())
        .unwrap_u8()
        != 1
    {
        return Err(BrokerBrowserError::InvalidRequest);
    }
    let url = std::str::from_utf8(&body[separator + 1..])
        .map_err(|_| BrokerBrowserError::InvalidRequest)?;
    validate_broker_browser_open_url(url)?;
    Ok(Some(url.to_owned()))
}

pub fn validate_broker_browser_open_url(url: &str) -> Result<(), BrokerBrowserError> {
    if url.is_empty() || url.len() > MAX_APPROVAL_URL_BYTES {
        return Err(BrokerBrowserError::InvalidRequest);
    }
    let parsed = url::Url::parse(url).map_err(|_| BrokerBrowserError::InvalidRequest)?;
    let production_origin = parsed.scheme() == "https"
        && matches!(parsed.host_str(), Some("palladin.io" | "stage.palladin.io"))
        && parsed.port().is_none();
    let local_origin = parsed.scheme() == "http"
        && parsed.port().is_some_and(|port| port != 0)
        && match parsed.host() {
            Some(url::Host::Ipv4(host)) => host.is_loopback(),
            Some(url::Host::Ipv6(host)) => host.is_loopback(),
            _ => false,
        };
    let pairing_id = parsed.path().strip_prefix("/agent-pairing/");
    let valid_pairing_id = pairing_id.is_some_and(|value| {
        !value.is_empty()
            && value.len() <= 128
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    });
    if (production_origin || local_origin)
        && valid_pairing_id
        && parsed.query().is_none()
        && parsed.fragment().is_none()
        && parsed.username().is_empty()
        && parsed.password().is_none()
    {
        Ok(())
    } else {
        Err(BrokerBrowserError::InvalidRequest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn broker_browser_request_round_trips_only_pinned_opaque_urls() {
        let binding = "ab".repeat(BROKER_BROWSER_OPEN_BINDING_BYTES);
        let url = "https://palladin.io/agent-pairing/3d8da884-19a7-4b37-a80c-7d09f0acdc01";
        let encoded = encode_broker_browser_open_request(&binding, url).expect("encoded request");
        assert_eq!(
            decode_broker_browser_open_request(encoded.as_bytes(), &binding)
                .expect("decoded request"),
            Some(url.to_owned())
        );
        assert!(decode_broker_browser_open_request(encoded.as_bytes(), &"cd".repeat(32)).is_err());

        for invalid in [
            "https://evil.example/agent-pairing/opaque",
            "https://palladin.io/agent-pairing/opaque?secret=value",
            "https://palladin.io/agent-pairing/opaque/extra",
            "http://localhost:5173/agent-pairing/opaque",
            "PALLADIN_BROKER_BROWSER_OPEN_V1:https://palladin.io/agent-pairing/opaque",
        ] {
            assert!(
                validate_broker_browser_open_url(invalid).is_err(),
                "{invalid}"
            );
        }
        assert!(
            validate_broker_browser_open_url("http://127.0.0.1:5173/agent-pairing/local-pairing")
                .is_ok()
        );
        assert!(
            validate_broker_browser_open_url("http://[::1]:5173/agent-pairing/local-pairing")
                .is_ok()
        );
        assert!(
            validate_broker_browser_open_url("http://127.0.0.1:45173/agent-pairing/local-pairing")
                .is_ok()
        );
    }

    #[test]
    fn non_control_stderr_is_not_consumed() {
        let binding = "ab".repeat(BROKER_BROWSER_OPEN_BINDING_BYTES);
        assert_eq!(
            decode_broker_browser_open_request(b"ordinary error\n", &binding)
                .expect("ordinary output"),
            None
        );
        assert!(
            decode_broker_browser_open_request(
                b"PALLADIN_BROKER_BROWSER_OPEN_V1:https://evil.example/agent-pairing/id\n",
                &binding,
            )
            .is_err()
        );
    }

    #[test]
    fn generated_binding_is_fixed_length_lowercase_hex() {
        let binding = generate_broker_browser_open_binding().expect("binding");
        validate_binding(&binding).expect("valid binding");
        assert_eq!(binding.len(), BROKER_BROWSER_OPEN_BINDING_BYTES * 2);
    }
}
