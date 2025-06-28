use aya::{Ebpf, include_bytes_aligned, programs::RawTracePoint, maps::perf::AsyncPerfEventArray};
use aya::maps::Array;
use aya::util::online_cpus;
use std::convert::TryInto;
use std::process::Command;
use anyhow::Context;
use log::{info};
use bytes::BytesMut;
use tokio::{signal, task};

const DATA_SIZE: usize = 64;

#[repr(C)]
#[derive(Debug, Clone)]
struct Event {
    pid: u32,
    data: [u8; DATA_SIZE],
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    let target_arch = "bpfel-unknown-none";
    let target_dir = std::env::var("CARGO_TARGET_DIR").unwrap_or_else(|_| "../target".to_string());

    #[cfg(debug_assertions)]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        concat!(env!("CARGO_MANIFEST_DIR"), "/../target/bpfel-unknown-none/debug/phase-2-data-capture")
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        concat!(env!("CARGO_MANIFEST_DIR"), "/../target/bpfel-unknown-none/release/phase-2-data-capture")
    ))?;

    let program: &mut RawTracePoint = bpf.program_mut("raw_tracepoint__sys_enter")
        .ok_or_else(|| anyhow::anyhow!("Program 'raw_tracepoint__sys_enter' not found"))?
        .try_into()?;

    program.load().context("Failed to load BPF program")?;
    program.attach("sys_enter").context("Failed to attach BPF program")?;
    info!("BPF program loaded and attached.");

    let mut perf_array = AsyncPerfEventArray::try_from(bpf.map_mut("events").unwrap())?;

    for cpu_id in online_cpus().map_err(|e| anyhow::anyhow!("Failed to get online cpus: {:?}", e))? {
        let mut buf = perf_array.open(cpu_id, None)?;

        task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(4096))
                .collect::<Vec<_>>();

            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                for i in 0..events.read {
                    let buf = &mut buffers[i];
                    let ptr = buf.as_ptr() as *const Event;
                    let event = unsafe { ptr.read_unaligned() };
                    let data_str = String::from_utf8_lossy(&event.data);
                    info!("PID: {}, Data: {}", event.pid, data_str.trim_end());
                }
            }
        });
    }


    // Spawn the child process
    let mut child = Command::new("/bin/echo")
        .arg("hello world!")
        .spawn()
        .context("Failed to spawn child process")?;
    let child_pid = child.id();
    info!("Child process started with PID: {}", child_pid);

    // Set the target PID in the eBPF program
    let mut config_map: Array<_, u32> = Array::try_from(bpf.map_mut("config_map").unwrap())?;
    config_map.set(0, child_pid, 0)?;
    info!("Target PID set in eBPF program.");

    // Wait for the child to exit or for Ctrl-C
    let child_wait = task::spawn_blocking(move || child.wait());

    tokio::select! {
        _ = signal::ctrl_c() => {
            info!("Ctrl-C received, exiting.");
        }
        status = child_wait => {
            info!("Child process exited with status: {:?}", status);
        }
    }

    info!("Exiting...");
    Ok(())
}