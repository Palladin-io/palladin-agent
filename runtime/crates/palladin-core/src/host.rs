use thiserror::Error;
use url::Url;

#[derive(Clone, Eq, PartialEq)]
pub struct ApiHost(Url);

impl ApiHost {
    pub fn parse(value: &str) -> Result<Self, ApiHostError> {
        let url = Url::parse(value).map_err(|_| ApiHostError::Invalid)?;
        let local_http = url.scheme() == "http" && url.host_str().is_some_and(is_local_host);
        if !(url.scheme() == "https" || local_http)
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.host_str().is_none()
        {
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
    #[error("API host must use HTTPS, except for literal loopback development hosts")]
    Invalid,
    #[error("API endpoint path is invalid")]
    InvalidEndpoint,
}

fn is_local_host(hostname: &str) -> bool {
    let hostname = hostname.to_ascii_lowercase();
    hostname == "localhost"
        || hostname.ends_with(".localhost")
        || hostname == "127.0.0.1"
        || matches!(hostname.as_str(), "::1" | "[::1]")
}

#[cfg(test)]
mod tests {
    use super::{ApiHost, ApiHostError};

    #[test]
    fn accepts_https_and_loopback_http() {
        assert!(ApiHost::parse("https://api.palladin.io").is_ok());
        assert!(ApiHost::parse("http://localhost:5000").is_ok());
        assert!(ApiHost::parse("http://worker.localhost:5000/base").is_ok());
        assert!(ApiHost::parse("http://127.0.0.1:5000").is_ok());
        assert!(ApiHost::parse("http://[::1]:5000").is_ok());
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
    }

    #[test]
    fn endpoint_cannot_escape_the_approved_origin() {
        let host = ApiHost::parse("https://api.palladin.io/base").expect("host");
        assert_eq!(
            host.endpoint("/api/agent/me").expect("endpoint").as_str(),
            "https://api.palladin.io/base/api/agent/me"
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
