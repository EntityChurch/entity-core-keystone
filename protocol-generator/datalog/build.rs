// Link the Datalog peer against libentitycore_codec (the C-ABI codec .so — canonical
// CBOR + Ed25519/Ed448 + SHA-256/384 + peer-id). In the datalog-toolchain image it is
// staged at $ENTITY_CODEC_DIR (/opt/entity-codec, built from the in-repo C source).
// This is the peer's ONLY crypto/CBOR/bytes dependency — Datalog never crosses it.
// Mirrors containers/datalog-toolchain/gogate/build.rs.
fn main() {
    let dir = std::env::var("ENTITY_CODEC_DIR").unwrap_or_else(|_| "/opt/entity-codec".to_string());
    println!("cargo:rustc-link-search=native={dir}");
    println!("cargo:rustc-link-lib=dylib=entitycore_codec");
    // rpath so the built binaries/tests resolve the .so at runtime without LD_LIBRARY_PATH.
    println!("cargo:rustc-link-arg=-Wl,-rpath,{dir}");
    println!("cargo:rerun-if-env-changed=ENTITY_CODEC_DIR");
}
