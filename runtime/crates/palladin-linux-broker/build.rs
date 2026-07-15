fn main() {
    println!("cargo:rerun-if-env-changed=PALLADIN_PRODUCTION_BUILD");
    if std::env::var("PALLADIN_PRODUCTION_BUILD").as_deref() == Ok("1")
        && std::env::var_os("CARGO_FEATURE_LOCAL_DEVELOPMENT").is_some()
    {
        panic!("production Linux broker builds cannot enable the local-development feature");
    }
}
