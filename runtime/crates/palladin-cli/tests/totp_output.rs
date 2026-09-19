use palladin_cli::output::{CredentialOutput, TotpOutput};
use palladin_credential::{
    fields::{FieldSelector, ResolvedField, redact_totp_secrets, resolve_field_at},
    secret::parse_secret,
};
use secrecy::ExposeSecret;

#[test]
fn protected_totp_source_never_enters_cli_get_json() {
    const SEED: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    let bytes = serde_json::to_vec(&serde_json::json!({"fields":[{"id":"credential.totp","label":"totp","type":"totp","value":{"source":"totp","secret":SEED,"algorithm":"SHA1","digits":8,"period":30}}]})).unwrap();
    let parsed = parse_secret(&bytes).unwrap();
    let ResolvedField::Totp {
        label,
        code,
        expires_in,
    } = resolve_field_at(
        &parsed,
        &FieldSelector {
            field: None,
            field_id: Some("credential.totp".into()),
        },
        59,
    )
    .unwrap()
    else {
        panic!("protected source must derive")
    };
    let selected = serde_json::to_string(&TotpOutput {
        entry_id: "fixture",
        label: "fixture",
        field: &label,
        code: code.expose_secret(),
        expires_in,
    })
    .unwrap();
    let redacted = redact_totp_secrets(&bytes, 59).unwrap();
    let full = serde_json::to_string(&CredentialOutput {
        entry_id: "fixture",
        label: "fixture",
        secret: redacted.expose_secret(),
    })
    .unwrap();
    for output in [selected, full] {
        assert!(!output.contains(SEED));
        assert!(!output.contains("source"));
        assert!(output.contains("94287082"));
    }
}
