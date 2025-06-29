use anyhow::Result;
use bytes::{Bytes, BytesMut};
use clap::{Parser, Subcommand};
use log::info;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time;

#[derive(Parser)]
#[clap(name = "audio-test-client")]
#[clap(about = "Test client for audio latency tracking")]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Send test audio pattern
    Send {
        #[clap(short, long, default_value = "127.0.0.1:8080")]
        target: String,

        #[clap(short, long, default_value = "1000")]
        interval_ms: u64,

        #[clap(short, long, default_value = "100")]
        count: usize,
    },

    /// Receive and forward audio
    Relay {
        #[clap(short, long, default_value = "127.0.0.1:8080")]
        listen: String,

        #[clap(short, long, default_value = "127.0.0.1:8081")]
        forward: String,
    },

    /// Just receive audio
    Sink {
        #[clap(short, long, default_value = "127.0.0.1:8081")]
        listen: String,
    },
}

/// Generate a simple WAV-like audio pattern
fn generate_audio_pattern(sequence: u32) -> Bytes {
    let mut buf = BytesMut::with_capacity(2048);

    // Simple WAV header (44 bytes)
    buf.extend_from_slice(b"RIFF");
    buf.extend_from_slice(&2004u32.to_le_bytes()); // ChunkSize
    buf.extend_from_slice(b"WAVE");
    buf.extend_from_slice(b"fmt ");
    buf.extend_from_slice(&16u32.to_le_bytes()); // Subchunk1Size
    buf.extend_from_slice(&1u16.to_le_bytes()); // AudioFormat (PCM)
    buf.extend_from_slice(&1u16.to_le_bytes()); // NumChannels
    buf.extend_from_slice(&8000u32.to_le_bytes()); // SampleRate
    buf.extend_from_slice(&16000u32.to_le_bytes()); // ByteRate
    buf.extend_from_slice(&2u16.to_le_bytes()); // BlockAlign
    buf.extend_from_slice(&16u16.to_le_bytes()); // BitsPerSample
    buf.extend_from_slice(b"data");
    buf.extend_from_slice(&1960u32.to_le_bytes()); // Subchunk2Size

    // Generate unique audio pattern based on sequence
    // This creates a simple sine-like pattern with varying frequency
    for i in 0..980 {
        let phase = (i as f32 * 0.1 * (sequence as f32).sin()).sin();
        let sample = (phase * 32767.0) as i16;
        buf.extend_from_slice(&sample.to_le_bytes());
    }

    buf.freeze()
}

async fn send_audio(target: &str, interval_ms: u64, count: usize) -> Result<()> {
    let mut stream = TcpStream::connect(target).await?;
    info!("Connected to {}", target);

    for i in 0..count {
        let pattern = generate_audio_pattern(i as u32);
        stream.write_all(&pattern).await?;

        info!("Sent audio pattern {} ({} bytes)", i, pattern.len());

        if i < count - 1 {
            time::sleep(Duration::from_millis(interval_ms)).await;
        }
    }

    Ok(())
}

async fn relay_audio(listen: &str, forward: &str) -> Result<()> {
    let listener = TcpListener::bind(listen).await?;
    info!("Relay listening on {}, forwarding to {}", listen, forward);

    loop {
        let (mut inbound, addr) = listener.accept().await?;
        info!("Accepted connection from {}", addr);

        let forward = forward.to_string();

        tokio::spawn(async move {
            match TcpStream::connect(&forward).await {
                Ok(mut outbound) => {
                    let mut buf = vec![0; 4096];

                    loop {
                        match inbound.read(&mut buf).await {
                            Ok(0) => break,
                            Ok(n) => {
                                if let Err(e) = outbound.write_all(&buf[..n]).await {
                                    eprintln!("Forward write error: {}", e);
                                    break;
                                }
                            }
                            Err(e) => {
                                eprintln!("Relay read error: {}", e);
                                break;
                            }
                        }
                    }
                }
                Err(e) => eprintln!("Failed to connect to forward target: {}", e),
            }
        });
    }
}

async fn sink_audio(listen: &str) -> Result<()> {
    let listener = TcpListener::bind(listen).await?;
    info!("Sink listening on {}", listen);

    loop {
        let (mut socket, addr) = listener.accept().await?;
        info!("Accepted connection from {}", addr);

        tokio::spawn(async move {
            let mut buf = vec![0; 4096];
            let mut total_bytes = 0;

            loop {
                match socket.read(&mut buf).await {
                    Ok(0) => {
                        info!(
                            "Connection from {} closed, received {} bytes",
                            addr, total_bytes
                        );
                        break;
                    }
                    Ok(n) => {
                        total_bytes += n;
                    }
                    Err(e) => {
                        eprintln!("Sink read error: {}", e);
                        break;
                    }
                }
            }
        });
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Send {
            target,
            interval_ms,
            count,
        } => {
            send_audio(&target, interval_ms, count).await?;
        }
        Commands::Relay { listen, forward } => {
            relay_audio(&listen, &forward).await?;
        }
        Commands::Sink { listen } => {
            sink_audio(&listen).await?;
        }
    }

    Ok(())
}
