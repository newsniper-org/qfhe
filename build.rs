use bindgen::builder;
use cbindgen::Config;
use std::env;
fn main() {
  let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();

  cbindgen::Builder::new()
    .with_crate(crate_dir)
    .with_language(cbindgen::Language::C)
    .with_cpp_compat(true)
    .with_include_guard("QFHE_H")
    .with_config(Config::from_file("cbindgen.toml").unwrap())
    .generate()
    .expect("Unable to generate bindings")
    .write_to_file("include/qfhe.h");
  builder()
      .header("include/qfhe.h")
      .enable_cxx_namespaces()
      .generate()
      .expect("Unable to generate bindings");     
}
