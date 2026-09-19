use super::*;
use crate::fields::{FieldSelector, ResolvedField, redact_totp_secrets, resolve_field_at};
use secrecy::ExposeSecret;

const SYNTHETIC_SEED: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

#[test]
fn shared_v2_sources_derive_each_rfc_code_and_expiry_for_both_field_ids() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../contracts/grant-payload/v2/vectors.json"
    ))
    .unwrap();
    for vector in fixture["vectors"].as_array().unwrap() {
        let bytes = vector["plaintextCanonical"].as_str().unwrap().as_bytes();
        for field in vector["plaintext"]["fields"].as_array().unwrap() {
            for derivation in vector["derivations"].as_array().unwrap() {
                let seconds = derivation["unixSeconds"].as_u64().unwrap();
                let result =
                    resolve_grant_payload_field_at(bytes, field["id"].as_str().unwrap(), seconds)
                        .unwrap();
                assert!(
                    result.value.expose_secret() == derivation["code"].as_str().unwrap(),
                    "derived fixture code must match the RFC vector"
                );
                let params = parse_totp_json(&field["value"]).unwrap();
                let code = crate::totp::generate_totp_at(&params, seconds).unwrap();
                assert_eq!(code.expires_in, derivation["expiresIn"].as_u64().unwrap());
            }
        }
    }
}

fn source() -> Value {
    serde_json::json!({"source":"totp","secret":SYNTHETIC_SEED,"algorithm":"SHA1","digits":8,"period":30})
}

#[test]
fn script_reference_v2_derives_at_each_operation_and_v1_stays_strict() {
    for id in [
        "credential.totp",
        "custom:11111111-1111-4111-8111-111111111111",
    ] {
        let mut payload = serde_json::json!({"schema":"palladin.grant-payload.v2","entryType":"credential","fields":[{"id":id,"kind":"totp","mode":"derived","value":source()}]});
        let bytes = serde_jcs::to_vec(&payload).unwrap();
        for (time, expected) in [(59, "94287082"), (1111111109, "07081804")] {
            let value = resolve_grant_payload_field_at(&bytes, id, time).unwrap();
            assert!(value.is_totp);
            assert!(
                value.value.expose_secret() == expected,
                "derived fixture code must match"
            );
            assert!(!format!("{value:?}").contains(SYNTHETIC_SEED));
        }
        payload["schema"] = serde_json::json!("palladin.grant-payload.v1");
        assert!(
            resolve_grant_payload_field_at(&serde_jcs::to_vec(&payload).unwrap(), id, 59).is_err()
        );
    }
}

#[test]
fn normalized_source_get_outputs_and_scalar_environment_never_contain_seed() {
    for id in ["credential.totp", "11111111-1111-4111-8111-111111111111"] {
        let bytes = serde_json::to_vec(&serde_json::json!({"fields":[{"id":id,"label":"totp","type":"totp","agentVisible":true,"value":source()}]})).unwrap();
        let parsed = parse_secret(&bytes).unwrap();
        assert!(
            parsed.fields.is_empty(),
            "TOTP source must never enter default scalar env"
        );
        for (time, expected) in [(59, "94287082"), (1111111109, "07081804")] {
            let selected = resolve_field_at(
                &parsed,
                &FieldSelector {
                    field: None,
                    field_id: Some(id.into()),
                },
                time,
            )
            .unwrap();
            assert!(matches!(
                &selected,
                ResolvedField::Totp { expires_in: 1, .. }
            ));
            assert!(
                selected.expose_for_authorized_operation() == expected,
                "derived fixture code must match"
            );
            let redacted = redact_totp_secrets(&bytes, time).unwrap();
            assert!(!redacted.expose_secret().contains(SYNTHETIC_SEED));
            assert!(!redacted.expose_secret().contains("\"source\""));
            assert!(redacted.expose_secret().contains(expected));
        }
        assert!(!format!("{parsed:?}").contains(SYNTHETIC_SEED));
    }
}
