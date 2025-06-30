# Audio Latency Tracker - Deployment Guide

## Quick Start

### Local Development
```bash
# Build everything
make build

# Run locally (requires root)
sudo INTERFACE=lo AUDIO_PORTS=8080,8081 ./target/debug/audio-latency
```

### Docker Build
```bash
# Build Docker image
docker build -t audio-latency-tracker:latest .

# Run with Docker
docker run --rm -it \
  --privileged \
  --network host \
  -e INTERFACE=eth0 \
  -e AUDIO_PORTS=8080,8081 \
  audio-latency-tracker:latest
```

### Kubernetes Deployment
```bash
# Set your registry (optional)
export REGISTRY=your-registry.com
export IMAGE_TAG=v1.0.0

# Deploy to Kubernetes
./deploy/deploy.sh

# Check status
kubectl get pods -n audio-latency-tracker

# View logs
kubectl logs -n audio-latency-tracker -l app=audio-latency-tracker -f

# Access metrics locally
kubectl port-forward -n audio-latency-tracker daemonset/audio-latency-tracker 9090:9090
curl http://localhost:9090/metrics
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `INTERFACE` | Network interface to monitor | `eth0` |
| `LOG_LEVEL` | Log level (trace, debug, info, warn, error) | `info` |
| `METRICS_PORT` | Prometheus metrics port | `9090` |
| `AUDIO_PORTS` | Comma-separated list of ports to monitor | all ports |
| `SIGNATURE_WINDOW_SIZE` | Bytes to sample for signature | `256` |
| `SILENCE_THRESHOLD` | PCM threshold for silence detection | `256` |
| `SIGNATURE_ALGORITHM` | Algorithm: rolling_hash, crc32, xxhash | `xxhash` |
| `K8S_ENABLED` | Enable Kubernetes pod lookup | auto-detect |
| `K8S_NODE_NAME` | Kubernetes node name | from Downward API |
| `CONTAINER_RUNTIME` | Container runtime: docker, containerd, crio, auto | `auto` |
| `MAX_FLOWS` | Maximum concurrent flows to track | `10000` |
| `FLOW_TIMEOUT_MS` | Flow state timeout in milliseconds | `30000` |
| `PERF_BUFFER_SIZE` | Per-CPU perf buffer size (must be power of 2) | `1024` |

### Customizing for Your Environment

1. **Audio Ports**: Update the ConfigMap to specify your audio service ports:
   ```yaml
   data:
     AUDIO_PORTS: "8080,8081,8082,9000"
   ```

2. **Network Interface**: If your pods use a different interface:
   ```yaml
   data:
     INTERFACE: "ens3"  # or whatever your interface is
   ```

3. **Signature Algorithm**: Choose based on your needs:
   - `rolling_hash`: Fastest, moderate collision resistance
   - `crc32`: Good balance of speed and collision resistance
   - `xxhash`: Best collision resistance, slightly slower

4. **Container Runtime**: Usually auto-detect works, but you can specify:
   ```yaml
   data:
     CONTAINER_RUNTIME: "containerd"  # or docker, crio
   ```

## Prometheus Integration

### Metrics Exposed

- `audio_latency_seconds`: Histogram of latency between components
- `audio_signatures_total`: Counter of signatures detected per pod
- `audio_signature_collisions_total`: Counter of hash collisions
- `audio_processing_errors_total`: Counter of processing errors

### Example Queries

```promql
# Average latency between specific pods
avg(rate(audio_latency_seconds_sum[5m]) / rate(audio_latency_seconds_count[5m])) 
  by (source_pod, dest_pod)

# 99th percentile latency
histogram_quantile(0.99, 
  sum(rate(audio_latency_seconds_bucket[5m])) 
  by (source_pod, dest_pod, le))

# Signature detection rate per pod
rate(audio_signatures_total[1m]) by (pod)

# Collision rate
rate(audio_signature_collisions_total[5m])
```

### Grafana Dashboard

Import the dashboard from `deploy/grafana-dashboard.json` (to be created).

## Troubleshooting

### No Signatures Detected

1. Verify traffic is flowing on monitored ports:
   ```bash
   kubectl exec -n audio-latency-tracker daemonset/audio-latency-tracker -- \
     tcpdump -i eth0 -n port 8080
   ```

2. Check eBPF program is loaded:
   ```bash
   kubectl exec -n audio-latency-tracker daemonset/audio-latency-tracker -- \
     bpftool prog list
   ```

3. Increase log level:
   ```bash
   kubectl set env -n audio-latency-tracker daemonset/audio-latency-tracker \
     LOG_LEVEL=debug
   ```

### High Collision Rate

- Switch to `xxhash` algorithm
- Increase `SIGNATURE_WINDOW_SIZE` (max 1024)

### Memory Usage

- Reduce `MAX_FLOWS` if memory is constrained
- Decrease `FLOW_TIMEOUT_MS` to clean up flows faster

### Permission Errors

Ensure the DaemonSet has required capabilities:
- `CAP_BPF` (or `CAP_SYS_ADMIN` on older kernels)
- `CAP_NET_ADMIN`

## Production Considerations

1. **Resource Limits**: Adjust based on your traffic volume
2. **Node Selectors**: Target specific nodes if needed
3. **Tolerations**: Already configured for all nodes
4. **Network Policies**: Allow metrics scraping from Prometheus
5. **PodSecurityPolicy**: May need exceptions for privileged mode

## Monitoring the Monitor

Set up alerts for the tracker itself:
```yaml
- alert: AudioLatencyTrackerDown
  expr: up{job="audio-latency-tracker"} == 0
  for: 5m
  
- alert: AudioLatencyTrackerHighMemory
  expr: container_memory_usage_bytes{pod=~"audio-latency-tracker.*"} > 400000000
  for: 5m
```