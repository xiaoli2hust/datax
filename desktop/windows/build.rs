fn main() {
    println!("cargo:rerun-if-env-changed=DES_RELEASE_MANIFEST_SHA256");
}
