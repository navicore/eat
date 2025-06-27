use aya::{Ebpf, include_bytes_aligned, programs::TracePoint};
use aya::maps::{HashMap, Array};
use std::convert::TryInto;
use std::process::Command;
use anyhow::Context;
use log::{info};

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    #[cfg(debug_assertions)]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../../target/bpfel-unknown-none/debug/phase-1-poc"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../../target/bpfel-unknown-none/release/phase-1-poc"
    ))?;

    let program: &mut TracePoint = bpf.program_mut("tracepoint__syscalls__sys_enter_write")
        .ok_or_else(|| anyhow::anyhow!("Program 'tracepoint__syscalls__sys_enter_write' not found"))?
        .try_into()?;

    program.load().context("Failed to load BPF program")?;
    program.attach("syscalls", "sys_enter_write").context("Failed to attach BPF program")?;

    // A small sleep to ensure the eBPF program is loaded and attached
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Spawn the child process
    let mut child = Command::new("/bin/echo")
        .arg("hello world")
        .spawn()
        .context("Failed to spawn child process")?;
    let child_pid = child.id();
    info!("Child process started with PID: {}", child_pid);

    // Set the target PID in the eBPF program
    let mut config_map: Array<_, u32> = Array::try_from(bpf.map_mut("config_map").ok_or_else(|| anyhow::anyhow!("Map 'config_map' not found"))?)?;
    config_map.set(0, child_pid, 0)?;


    info!("BPF program loaded.");

    let signatures_map: HashMap<_, u32, u64> = HashMap::try_from(bpf.map_mut("signatures").ok_or_else(|| anyhow::anyhow!("Map 'signatures' not found"))?)?;

    info!("Signatures map initialized.");

    // Wait for the child to exit
    let status = child.wait().context("Failed to wait for child process")?;
    info!("Child process exited with status: {}", status);

    // Give the eBPF program some time to process the event.
    for _ in 0..10 {
        tokio::task::yield_now().await;
        if signatures_map.iter().next().is_some() {
            break;
        }
    }

    // Read from the map
    for entry in signatures_map.iter() {
        let (pid, signature): (u32, u64) = entry?;
        info!("Map Entry: PID={}, Signature={:#x}", pid, signature);
    }

    info!("Exiting...");

    Ok(())
}