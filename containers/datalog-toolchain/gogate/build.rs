// Link the GO-gate binary against libentitycore_codec (the C-ABI codec .so built
// earlier in the image at /opt/entity-codec). The peer's ONLY crypto/codec/bytes
// dependency crosses this same seam; the KAT below proves the seam links + calls.
fn main() {
    let dir = std::env::var("ENTITY_CODEC_DIR").unwrap_or_else(|_| "/opt/entity-codec".to_string());
    println!("cargo:rustc-link-search=native={dir}");
    println!("cargo:rustc-link-lib=dylib=entitycore_codec");
    // rpath so the binary resolves the .so at runtime without LD_LIBRARY_PATH.
    println!("cargo:rustc-link-arg=-Wl,-rpath,{dir}");
    println!("cargo:rerun-if-env-changed=ENTITY_CODEC_DIR");
}
