/// Build script for zkp-python (PyO3 cdylib).
///
/// On macOS, the Python3 framework does not automatically expose its symbols
/// to the linker when building a `cdylib`. This script resolves the arm64
/// linker error: "symbol(s) not found for architecture arm64".
///
/// Strategy: use `-undefined dynamic_lookup` instead of linking the Python
/// framework directly. This is the standard approach for Python extension
/// modules — symbols are resolved at import time by the CPython runtime.
fn main() {
    if cfg!(target_os = "macos") {
        println!("cargo:rustc-link-arg=-undefined");
        println!("cargo:rustc-link-arg=dynamic_lookup");
    }
}
