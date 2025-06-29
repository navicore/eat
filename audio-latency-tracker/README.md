# Audio Latency Tracker

A fully Rust-based eBPF solution for tracking audio latency across distributed systems using TC (Traffic Control) hooks.

## Architecture

- **audio-latency-ebpf**: eBPF program that attaches to TC ingress and calculates audio signatures
- **audio-latency**: Userspace daemon that loads the eBPF program and processes events
- **audio-test-client**: Test application for generating and relaying audio streams

## Building

```bash
# Install dependencies
rustup toolchain install nightly
rustup component add rust-src --toolchain nightly

# Build everything
cargo build --release
```

## Testing

### 1. Start the eBPF tracker (requires root):

```bash
sudo ./target/release/audio-latency -i eth0
```

### 2. In another terminal, start a relay:

```bash
./target/release/audio-test-client relay -l 127.0.0.1:8080 -f 127.0.0.1:8081
```

### 3. In another terminal, start a sink:

```bash
./target/release/audio-test-client sink -l 127.0.0.1:8081
```

### 4. Send test audio:

```bash
./target/release/audio-test-client send -t 127.0.0.1:8080 -c 10
```

## How It Works

1. The eBPF program attaches to TC ingress on the specified network interface
2. For each TCP packet, it extracts payload data and calculates an audio signature using a rolling hash
3. Non-silence audio signatures are reported via perf events to userspace
4. The userspace daemon tracks signatures and calculates latency when the same signature appears at different points

## Debugging TC Attachment Issues

If TC isn't capturing packets:

1. Verify interface name: `ip link show`
2. Check TC filters: `tc filter show dev eth0 ingress`
3. Try loopback first: `sudo ./target/release/audio-latency -i lo`
4. Check kernel logs: `sudo dmesg | tail`
5. Use tcpdump to verify traffic: `sudo tcpdump -i eth0 port 8080`

## Next Steps

- Add XDP support as alternative to TC
- Implement more sophisticated audio pattern detection
- Add Kubernetes DaemonSet deployment
- Export metrics to Prometheus