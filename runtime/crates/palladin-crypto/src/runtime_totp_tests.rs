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
        value["secret"] = serde_json::json!(format!("{}{}", "A".repeat(24), seed));
        crate::validate_runtime_totp_source(&value).unwrap();
    }
    for seed in ["", "A", "MY", "MZXQ", "MZXW6", "MZXW6YQ", "MZXW6YTB"] {
        let mut value = source();
        value["secret"] = serde_json::json!(seed);
        assert!(crate::validate_runtime_totp_source(&value).is_err());
    }
    for suffix in [
        "A", "AAA", "AAAAAA", "MZ", "MZXR", "MZXW7", "MZXW6YR", "MY======", "my",
    ] {
        let mut value = source();
        value["secret"] = serde_json::json!(format!("{}{}", "A".repeat(24), suffix));
        assert!(crate::validate_runtime_totp_source(&value).is_err());
    }
    let mut value = source();
    value["secret"] = serde_json::json!("A".repeat(24));
    assert!(
        crate::validate_runtime_totp_source(&value).is_err(),
        "15-byte source must be rejected"
    );
    value["secret"] = serde_json::json!("A".repeat(26));
    crate::validate_runtime_totp_source(&value).unwrap();
    value["secret"] = serde_json::json!("A".repeat(1024));
    crate::validate_runtime_totp_source(&value).unwrap();
    value["secret"] = serde_json::json!("A".repeat(1032));
    assert!(crate::validate_runtime_totp_source(&value).is_err());
}

fn full_member_secret_with_totp() -> Value {
    let mut totp = source();
    totp.as_object_mut().unwrap().remove("source");
    totp["issuer"] = serde_json::json!("Synthetic issuer");
    totp["account"] = serde_json::json!("synthetic@example.invalid");
    serde_json::json!({
        "schema": "palladin.member-secret.v1",
        "memberLabel": "Synthetic account", "agentLabel": "Synthetic account",
        "description": null, "color": null, "icon": null, "discoverable": true,
        "entryType": "credential",
        "agentFieldAccess": {
            "memberLabel": "never", "agentLabel": "discovery", "description": "never",
            "color": "never", "icon": "never", "entryType": "discovery",
            "credential.username": "onGrantValue", "credential.password": "onGrantValue",
            "credential.url": "onGrantValue", "credential.urlDomain": "discovery",
            "credential.totp": "onGrantDerived", "notes": "never"
        },
        "content": {
            "username": "synthetic-user", "password": "synthetic-password",
            "url": "https://example.invalid/login", "urlDomain": "example.invalid",
            "totp": totp, "notes": null, "customFields": []
        }
    })
}

#[test]
fn full_member_secret_totp_is_projected_as_runtime_source_for_inject() {
    let secret = serde_json::to_vec(&full_member_secret_with_totp()).unwrap();
    let normalized = normalize_full_member_secret(&secret, 4, 0)
        .expect("FULL MemberSecret TOTP source must remain usable for Inject");
    let value: Value = serde_json::from_slice(&normalized.plaintext).unwrap();
    assert_eq!(value["username"], "synthetic-user");
    assert_eq!(value["password"], "synthetic-password");
    assert_eq!(value["fields"][0]["id"], "credential.totp");
    assert_eq!(value["fields"][0]["type"], "totp");
    assert_eq!(value["fields"][0]["value"], source());
}

#[test]
fn full_member_totp_policy_never_and_null_do_not_deliver_a_source() {
    for value in [
        Value::Null,
        serde_json::json!({"invalid": "ungranted-source"}),
    ] {
        let mut member = full_member_secret_with_totp();
        member["content"]["totp"] = value.clone();
        if !value.is_null() {
            member["agentFieldAccess"]["credential.totp"] = serde_json::json!("never");
        }
        let normalized = normalize_full_member_secret(&serde_json::to_vec(&member).unwrap(), 4, 0)
            .expect("unselected or absent TOTP must not prevent password Inject");
        let result: Value = serde_json::from_slice(&normalized.plaintext).unwrap();
        assert!(result.get("fields").is_none());
        assert_eq!(result["password"], "synthetic-password");
    }
}

#[test]
fn full_custom_totp_preserves_policy_and_id_for_key_and_credential() {
    let id = "custom:11111111-1111-4111-8111-111111111111";
    for entry_type in ["key", "credential"] {
        for mode in ["never", "onGrantDerived"] {
            let mut member = full_member_secret_with_totp();
            let totp = member["content"]["totp"].take();
            member["agentFieldAccess"]["credential.totp"] = serde_json::json!("never");
            if entry_type == "key" {
                member["entryType"] = serde_json::json!("key");
                member["agentFieldAccess"]
                    .as_object_mut()
                    .unwrap()
                    .retain(|key, _| !key.starts_with("credential."));
                member["agentFieldAccess"]["key.value"] = serde_json::json!("onGrantValue");
                member["agentFieldAccess"]["key.url"] = serde_json::json!("onGrantValue");
                member["content"] = serde_json::json!({
                    "value": "synthetic-key", "url": "https://example.invalid", "notes": null
                });
            }
            member["content"]["customFields"] = serde_json::json!([
                {"id": id, "label": "Synthetic TOTP", "type": "totp", "value": totp}
            ]);
            member["agentFieldAccess"][id] = serde_json::json!(mode);
            for method in [1, 2, 4] {
                let normalized =
                    normalize_full_member_secret(&serde_json::to_vec(&member).unwrap(), method, 0)
                        .expect("FULL custom TOTP policy projection");
                let result: Value = serde_json::from_slice(&normalized.plaintext).unwrap();
                if mode == "never" {
                    assert!(result.get("fields").is_none());
                } else {
                    assert_eq!(
                        result["fields"][0]["id"],
                        id.strip_prefix("custom:").unwrap()
                    );
                    assert_eq!(result["fields"][0]["value"], source());
                }
            }
        }
    }
}

#[test]
fn full_member_totp_rejects_invalid_sources_without_bypassing_the_v2_validator() {
    for (key, value) in [
        ("secret", serde_json::json!("invalid-base32")),
        ("algorithm", serde_json::json!("MD5")),
        ("digits", serde_json::json!(7)),
        ("period", serde_json::json!(0)),
        ("unexpected", serde_json::json!(true)),
        ("issuer", serde_json::json!({"unexpected": true})),
    ] {
        let mut member = full_member_secret_with_totp();
        member["content"]["totp"][key] = value;
        assert!(normalize_full_member_secret(&serde_json::to_vec(&member).unwrap(), 4, 0).is_err());
    }
    let mut member = full_member_secret_with_totp();
    member["agentFieldAccess"]["credential.totp"] = serde_json::json!("onGrantValue");
    assert!(normalize_full_member_secret(&serde_json::to_vec(&member).unwrap(), 4, 0).is_err());
}
