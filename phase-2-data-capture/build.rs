use std::process::Command;

fn main() {
    // Trigger a rebuild when the C code changes.
    println!("cargo:rerun-if-changed=src/ebpf/tracer.c");

    // Get the kernel version dynamically
    let uname_output = Command::new("uname")
        .arg("-r")
        .output()
        .expect("Failed to get kernel version");
    let kernel_version = String::from_utf8_lossy(&uname_output.stdout).trim().to_string();

    let profile = std::env::var("PROFILE").unwrap_or_else(|_| "debug".to_string());
    let out_dir = format!("../../target/bpfel-unknown-none/{}", profile);
    std::fs::create_dir_all(&out_dir).expect("Failed to create bpf output directory");
    let out_file = format!("{}/phase-1-poc", out_dir);

    // Build the eBPF code.
    let output = Command::new("clang")
        .args(&[
            "-c",
            "-target", "bpf",
            "-D", "__BPF_TRACING__",
            "-I", "/usr/include/bpf",
            "-I", &format!("/usr/src/kernels/{}/include", kernel_version),
            "-I", &format!("/usr/src/kernels/{}/include/uapi", kernel_version),
            "-I", &format!("/usr/src/kernels/{}/arch/x86/include", kernel_version),
            "-I", &format!("/usr/src/kernels/{}/arch/x86/include/uapi", kernel_version),
            "-I", &format!("/usr/src/kernels/{}/arch/x86/include/generated", kernel_version),
            "-I", &format!("/usr/src/kernels/{}/include/trace/events", kernel_version),
            "-O2",
            "-g", // Emit BTF information
            "-o", &out_file,
            "src/ebpf/tracer.c",
        ])
        .output()
        .expect("Failed to compile eBPF code");

    if !output.status.success() {
        panic!(
            "Failed to compile eBPF code: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}