use secrecy::{ExposeSecret, SecretSlice, SecretString};

#[derive(Debug)]
pub struct OrganizationApiKey(SecretString);

impl OrganizationApiKey {
    #[must_use]
    pub fn new(value: String) -> Self {
        Self(value.into())
    }

    #[must_use]
    pub fn expose_for_authorized_request(&self) -> &str {
        self.0.expose_secret()
    }
}

#[derive(Debug)]
pub struct AgentPrivateKey(SecretSlice<u8>);

impl AgentPrivateKey {
    #[must_use]
    pub fn new(value: Vec<u8>) -> Self {
        Self(value.into())
    }

    #[must_use]
    pub fn expose_for_authorized_operation(&self) -> &[u8] {
        self.0.expose_secret()
    }
}

#[cfg(test)]
mod tests {
    use super::{AgentPrivateKey, OrganizationApiKey};

    #[test]
    fn debug_output_is_redacted() {
        let api_key = OrganizationApiKey::new("pl_example_secret".to_owned());
        let private_key = AgentPrivateKey::new(b"private-key-material".to_vec());

        let output = format!("{api_key:?} {private_key:?}");
        assert!(!output.contains("pl_example_secret"));
        assert!(!output.contains("private-key-material"));
        assert!(output.contains("[REDACTED]"));
    }
}
