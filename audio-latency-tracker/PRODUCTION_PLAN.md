# Production Deployment Plan

## Architecture Overview

The audio latency tracker will run as a DaemonSet on every Kubernetes node, tracking audio signatures across pods and reporting metrics via Prometheus.

## Environment Variables

### Core Configuration
- `INTERFACE`: Network interface to monitor (default: `eth0`)
- `LOG_LEVEL`: Logging level (default: `info`)
- `METRICS_PORT`: Prometheus metrics port (default: `9090`)

### Audio Processing
- `AUDIO_PORTS`: Comma-separated list of ports to monitor (default: all)
- `SIGNATURE_WINDOW_SIZE`: Bytes to sample for signature (default: `256`)
- `SILENCE_THRESHOLD`: PCM threshold for silence detection (default: `256`)
- `SIGNATURE_ALGORITHM`: Algorithm to use (`rolling_hash`, `crc32`, `xxhash`) (default: `xxhash`)

### Kubernetes Integration
- `K8S_ENABLED`: Enable Kubernetes pod lookup (default: `true` in k8s)
- `K8S_NODE_NAME`: Node name (from Downward API)
- `CONTAINER_RUNTIME`: Runtime to parse (`docker`, `containerd`, `crio`) (default: auto-detect)

### Performance Tuning
- `MAX_FLOWS`: Maximum concurrent flows to track (default: `10000`)
- `FLOW_TIMEOUT_MS`: Flow state timeout in milliseconds (default: `30000`)
- `PERF_BUFFER_SIZE`: Per-CPU perf buffer size (default: `1024`)

## Implementation Phases

### Phase 1: Enhanced Signature Algorithm
1. Add xxHash for better distribution
2. Implement CRC32 as lightweight option
3. Add configurable window size
4. Improve silence detection with RMS

### Phase 2: Container Identification
1. Parse /proc/{pid}/cgroup for container IDs
2. Map container IDs to K8s pods via:
   - Local kubelet API
   - K8s API server (fallback)
3. Cache pod metadata

### Phase 3: Prometheus Metrics
```prometheus
# HELP audio_latency_seconds Audio latency between components
# TYPE audio_latency_seconds histogram
audio_latency_seconds_bucket{source_pod="ingress-1",dest_pod="processor-2",le="0.001"} 45
audio_latency_seconds_bucket{source_pod="ingress-1",dest_pod="processor-2",le="0.005"} 120
audio_latency_seconds_bucket{source_pod="ingress-1",dest_pod="processor-2",le="0.01"} 200
audio_latency_seconds_bucket{source_pod="ingress-1",dest_pod="processor-2",le="0.05"} 250
audio_latency_seconds_bucket{source_pod="ingress-1",dest_pod="processor-2",le="0.1"} 260
audio_latency_seconds_bucket{source_pod="ingress-1",dest_pod="processor-2",le="+Inf"} 262

# HELP audio_signatures_total Total audio signatures detected
# TYPE audio_signatures_total counter
audio_signatures_total{pod="ingress-1"} 1523

# HELP audio_signature_collisions_total Signature hash collisions detected
# TYPE audio_signature_collisions_total counter
audio_signature_collisions_total 2
```

### Phase 4: Kubernetes Deployment
1. Multi-stage Dockerfile with eBPF compilation
2. DaemonSet with proper security contexts
3. ConfigMap for environment variables
4. RBAC for pod/node API access

### Phase 5: Port Filtering
1. Parse AUDIO_PORTS environment variable
2. Add eBPF map for allowed ports
3. Early exit in eBPF for non-audio traffic

### Phase 6: Packet Reassembly
1. Per-flow state tracking in eBPF maps
2. Sliding window for cross-packet signatures
3. TCP sequence number tracking
4. Configurable reassembly timeout

## Directory Structure
```
audio-latency-tracker/
├── audio-latency-ebpf/          # eBPF program
├── audio-latency/               # Main daemon
│   ├── src/
│   │   ├── main.rs             # Entry point
│   │   ├── config.rs           # Env var parsing
│   │   ├── metrics.rs          # Prometheus exporter
│   │   ├── k8s.rs              # Kubernetes integration
│   │   ├── signature.rs        # Signature algorithms
│   │   └── container.rs        # Container ID extraction
├── deploy/                      # Kubernetes manifests
│   ├── daemonset.yaml
│   ├── configmap.yaml
│   ├── rbac.yaml
│   └── service.yaml
├── Dockerfile
└── Makefile
```

## Security Considerations
- Minimal container image (distroless)
- Read-only root filesystem
- Non-root user (with CAP_BPF, CAP_NET_ADMIN)
- Network policies for metrics endpoint
- No external dependencies in runtime container