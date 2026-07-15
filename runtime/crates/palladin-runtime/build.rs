use base64::{Engine, engine::general_purpose::STANDARD};

fn main() {
    for name in [
        "PALLADIN_PRODUCTION_BUILD",
        "PALLADIN_VERSION_POLICY_PUBLIC_KEY",
        "PALLADIN_VERSION_POLICY_BUNDLE_BASE64",
        "SOURCE_SHA",
    ] {
        println!("cargo:rerun-if-env-changed={name}");
    }
    if std::env::var("PALLADIN_PRODUCTION_BUILD").as_deref() != Ok("1") {
        return;
    }
    let key = std::env::var("PALLADIN_VERSION_POLICY_PUBLIC_KEY")
        .expect("production build requires the public version-policy key");
    let decoded = STANDARD
        .decode(&key)
        .expect("version-policy public key must be canonical base64");
    assert!(
        decoded.len() == 32
            && STANDARD.encode(&decoded) == key
            && decoded.iter().any(|byte| *byte != 0),
        "production build rejects an invalid or placeholder version-policy public key"
    );
    let source = std::env::var("SOURCE_SHA")
        .expect("production build requires the exact release SOURCE_SHA");
    assert!(
        source.len() == 40
            && source
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            && source.bytes().any(|byte| byte != b'0'),
        "production build rejects an invalid or placeholder SOURCE_SHA"
    );
}
