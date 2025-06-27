use aya_builder::build;
use std::path::PathBuf;

fn main() {
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap();

    let mut builder = build();
    builder.source_file("src/ebpf/tracer.c");
    builder.build().unwrap();

    println!("cargo:rerun-if-changed=src/ebpf/tracer.c");
}