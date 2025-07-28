#![feature(f128)]
#![feature(random)]

use bindgen::builder;

fn main() {
    builder()
        .header("include/qfhe.h")
        .enable_cxx_namespaces()
        .generate()
        .expect("Unable to generate bindings");     
}
