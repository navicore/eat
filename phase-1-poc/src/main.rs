use aya::Bpf;
use std::convert::TryInto;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let mut bpf = Bpf::load_file("target/tracer.o")?;
    let probe = bpf.program_mut("tracepoint__syscalls__sys_enter_write").unwrap().try_into()?;
    bpf.attach("tracepoint/syscalls/sys_enter_write", probe)?;

    println!("Waiting for Ctrl-C...");
    tokio::signal::ctrl_c().await?;

    Ok(())
}
