use super::*;

#[test]
fn shared_v2_vectors_are_byte_exact_and_preserve_v1_rejection() {
    use sha2::{Digest, Sha256};
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../contracts/grant-payload/v2/vectors.json"
    ))
    .unwrap();
    for vector in fixture["vectors"].as_array().unwrap() {
        let bytes = vector["plaintextCanonical"].as_str().unwrap().as_bytes();
        assert_eq!(hex::encode(bytes), vector["plaintextHex"].as_str().unwrap());
        assert_eq!(
            hex::encode(Sha256::digest(bytes)),
            vector["plaintextSha256"].as_str().unwrap()
        );
        let ids = vector["plaintext"]["fields"]
            .as_array()
            .unwrap()
            .iter()
            .map(|field| field["id"].as_str().unwrap().to_owned())
            .collect::<Vec<_>>();
        normalize_grant_payload(bytes, &ids, 1).expect("shared source vector");
        let mut old = vector["plaintext"].clone();
        old["schema"] = serde_json::json!("palladin.grant-payload.v1");
        assert!(normalize_grant_payload(&serde_json::to_vec(&old).unwrap(), &ids, 1).is_err());
    }
    for invalid in fixture["invalidSources"].as_array().unwrap() {
        let bytes = serde_json::to_vec(&invalid["plaintext"]).unwrap();
        assert!(
            normalize_grant_payload(&bytes, &["credential.totp".into()], 1).is_err(),
            "{}",
            invalid["id"]
        );
    }
}

fn source() -> Value {
    serde_json::json!({"source":"totp","secret":"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ","algorithm":"SHA1","digits":8,"period":30})
}

fn payload(schema: &str, id: &str, value: Value) -> Vec<u8> {
    serde_json::to_vec(
        &serde_json::json!({"schema":schema,"entryType":"credential","fields":[
            {"id":id,"kind":"totp","mode":"derived","value":value}
        ]}),
    )
    .unwrap()
}

#[test]
fn v2_retains_runtime_source_type_and_consistent_custom_id() {
    for id in [
        "credential.totp",
        "custom:11111111-1111-4111-8111-111111111111",
    ] {
        let bytes = payload("palladin.grant-payload.v2", id, source());
        let result = normalize_grant_payload(&bytes, &[id.to_owned()], 1).expect("v2 source");
        let normalized: Value = serde_json::from_slice(&result.plaintext).unwrap();
        assert_eq!(normalized["fields"][0]["type"], "totp");
        assert_eq!(
            normalized["fields"][0]["id"],
            id.strip_prefix("custom:").unwrap_or(id)
        );
        assert!(normalized["fields"][0]["value"]["secret"].is_string());
        assert!(normalized["fields"][0]["value"].get("code").is_none());
    }
}

#[test]
fn source_is_rejected_by_v1_and_invalid_v2_shapes_fail_closed() {
    let id = "credential.totp";
    assert!(
        normalize_grant_payload(
            &payload("palladin.grant-payload.v1", id, source()),
            &[id.into()],
            1
        )
        .is_err()
    );
    for (key, value) in [
        ("source", serde_json::json!("other")),
        ("secret", serde_json::json!("mzxw6===")),
        ("secret", serde_json::json!("MZ")),
        ("secret", serde_json::json!("A")),
        ("algorithm", serde_json::json!("MD5")),
        ("digits", serde_json::json!(7)),
        ("period", serde_json::json!(14)),
        ("period", serde_json::json!(121)),
        ("code", serde_json::json!("123456")),
    ] {
        let mut malformed = source();
        malformed[key] = value;
        assert!(
            normalize_grant_payload(
                &payload("palladin.grant-payload.v2", id, malformed),
                &[id.into()],
                1
            )
            .is_err()
        );
    }
}

#[test]
fn v2_source_has_strict_bounds_and_canonical_base32_residual_bits() {
    for seed in ["MY", "MZXQ", "MZXW6", "MZXW6YQ", "MZXW6YTB"] {
        let mut value = source();
        value["secret"] = serde_json::json!(seed);
        crate::validate_runtime_totp_source(&value).unwrap();
    }
    for seed in [
        "", "A", "AAA", "AAAAAA", "MZ", "MZXR", "MZXW7", "MZXW6YR", "MY======", "my",
    ] {
        let mut value = source();
        value["secret"] = serde_json::json!(seed);
        assert!(crate::validate_runtime_totp_source(&value).is_err());
    }
    let mut value = source();
    value["secret"] = serde_json::json!("A".repeat(1024));
    crate::validate_runtime_totp_source(&value).unwrap();
    value["secret"] = serde_json::json!("A".repeat(1032));
    assert!(crate::validate_runtime_totp_source(&value).is_err());
}
