use std::env;

fn main() {
    let version = env!("CARGO_PKG_VERSION");
    let description = env!("CARGO_PKG_DESCRIPTION");
    let homepage = env!("CARGO_PKG_HOMEPAGE");

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rustc-env=APP_NAME=disbin");
    println!("cargo:rustc-env=APP_DESCRIPTION={}", description);
    println!("cargo:rustc-env=APP_VERSION={}", version);
    println!("cargo:rustc-env=APP_HOMEPAGE={}", homepage);
}