use thiserror::Error;
use url::{Host, Url};

const PRODUCTION_ORIGIN: &str = "https://api.palladin.io";

#[derive(Clone, Eq, PartialEq)]
pub struct ApiHost(Url);

impl ApiHost {
    pub fn parse(value: &str) -> Result<Self, ApiHostError> {
        let url = Url::parse(value).map_err(|_| ApiHostError::Invalid)?;
        let has_root_path_only = url.path() == "/";
        let has_url_extras = !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some();
        if has_url_extras || !has_root_path_only {
            return Err(ApiHostError::Invalid);
        }

        let production = value == PRODUCTION_ORIGIN
            && url.scheme() == "https"
            && url.host_str() == Some("api.palladin.io")
            && url.port().is_none();
        let literal_loopback = matches!(
            url.host(),
            Some(Host::Ipv4(address)) if address == std::net::Ipv4Addr::LOCALHOST
        ) || matches!(
            url.host(),
            Some(Host::Ipv6(address)) if address == std::net::Ipv6Addr::LOCALHOST
        );
        let local_http = cfg!(feature = "local-development")
            && url.scheme() == "http"
            && url.port().is_some_and(|port| port != 0)
            && literal_loopback;
        if !production && !local_http {
            return Err(ApiHostError::Invalid);
        }
        Ok(Self(url))
    }

    pub fn endpoint(&self, path_with_query: &str) -> Result<Url, ApiHostError> {
        if !path_with_query.starts_with('/')
            || path_with_query.starts_with("//")
            || path_with_query.contains(['\r', '\n'])
        {
            return Err(ApiHostError::InvalidEndpoint);
        }

        let base = self.0.as_str().trim_end_matches('/');
        let endpoint = Url::parse(&format!("{base}{path_with_query}"))
            .map_err(|_| ApiHostError::InvalidEndpoint)?;
        if endpoint.scheme() != self.0.scheme()
            || endpoint.host_str() != self.0.host_str()
            || endpoint.port_or_known_default() != self.0.port_or_known_default()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.fragment().is_some()
        {
            return Err(ApiHostError::InvalidEndpoint);
        }
        Ok(endpoint)
    }

    #[must_use]
    pub fn as_url(&self) -> &Url {
        &self.0
    }
}

impl std::fmt::Debug for ApiHost {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_tuple("ApiHost").field(&self.0).finish()
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum ApiHostError {
    #[error("API host is not permitted by this build's pinned-origin policy")]
    Invalid,
    #[error("API endpoint path is invalid")]
    InvalidEndpoint,
}

#[cfg(test)]
mod tests {
    use super::{ApiHost, ApiHostError};

    #[test]
    fn accepts_pinned_production() {
        assert!(ApiHost::parse("https://api.palladin.io").is_ok());
    }

    #[cfg(feature = "local-development")]
    #[test]
    fn local_development_build_accepts_literal_loopback_http() {
        assert!(ApiHost::parse("http://127.0.0.1:5000").is_ok());
        assert!(ApiHost::parse("http://[::1]:5000").is_ok());
    }

    #[cfg(not(feature = "local-development"))]
    #[test]
    fn production_build_rejects_loopback_http() {
        assert_eq!(
            ApiHost::parse("http://127.0.0.1:5000"),
            Err(ApiHostError::Invalid)
        );
        assert_eq!(
            ApiHost::parse("http://[::1]:5000"),
            Err(ApiHostError::Invalid)
        );
    }

    #[test]
    fn rejects_cleartext_remote_and_embedded_credentials() {
        assert_eq!(
            ApiHost::parse("http://api.palladin.io"),
            Err(ApiHostError::Invalid)
        );
        assert_eq!(
            ApiHost::parse("https://user:secret@api.palladin.io"),
            Err(ApiHostError::Invalid)
        );
        assert_eq!(
            ApiHost::parse("https://api.palladin.io?key=secret"),
            Err(ApiHostError::Invalid)
        );
        for untrusted in [
            "https://api.palladin.io/",
            "https://api.palladin.io:443",
            "https://api.palladin.io/base",
            "https://attacker.test",
            "http://localhost:5000",
            "http://worker.localhost:5000",
            "http://127.0.0.1",
            "http://192.168.1.5:5000",
        ] {
            assert_eq!(ApiHost::parse(untrusted), Err(ApiHostError::Invalid));
        }
    }

    #[test]
    fn endpoint_cannot_escape_the_approved_origin() {
        let host = ApiHost::parse("https://api.palladin.io").expect("host");
        assert_eq!(
            host.endpoint("/api/agent/me").expect("endpoint").as_str(),
            "https://api.palladin.io/api/agent/me"
        );
        assert_eq!(
            host.endpoint("//attacker.test/steal"),
            Err(ApiHostError::InvalidEndpoint)
        );
        assert_eq!(
            host.endpoint("https://attacker.test/steal"),
            Err(ApiHostError::InvalidEndpoint)
        );
    }
}
