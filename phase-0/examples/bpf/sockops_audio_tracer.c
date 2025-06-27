// sockops_audio_tracer.c - SockOps eBPF program for audio pattern detection
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Constants
#define AUDIO_PORT_SOURCE 8000
#define AUDIO_PORT_RELAY 8001

// Event types
#define EVENT_TCP_CONNECT    1
#define EVENT_TCP_ACCEPT     2
#define EVENT_DATA_SENT      3
#define EVENT_DATA_RECEIVED  4

// Event structure for userspace
struct audio_event {
    __u64 timestamp_ns;
    __u32 pid;           // Process ID
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 event_type;     // Connection or data event
    __u32 bytes;         // Bytes sent/received
    __u32 duration_ns;   // RTT for data events
    __u8 _pad[3];
};

// Map for sending events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256KB buffer
} events SEC(".maps");

// Helper to create and submit event
static __always_inline void submit_event(struct bpf_sock_ops *skops, __u8 event_type, __u32 bytes) {
    struct audio_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return;
    
    __builtin_memset(event, 0, sizeof(*event));
    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->src_ip = skops->local_ip4;
    event->dst_ip = skops->remote_ip4;
    event->src_port = bpf_ntohs(skops->local_port);
    event->dst_port = skops->remote_port;
    event->event_type = event_type;
    event->bytes = bytes;
    event->duration_ns = skops->srtt_us * 1000; // Convert RTT to nanoseconds
    
    bpf_ringbuf_submit(event, 0);
}

SEC("sockops")
int sockops_audio_tracer(struct bpf_sock_ops *skops) {
    __u32 op = skops->op;
    __u16 local_port = bpf_ntohs(skops->local_port);
    __u16 remote_port = skops->remote_port;
    
    // Only track audio service ports
    if (local_port != AUDIO_PORT_SOURCE && local_port != AUDIO_PORT_RELAY &&
        remote_port != AUDIO_PORT_SOURCE && remote_port != AUDIO_PORT_RELAY)
        return 0;
    
    switch (op) {
    case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
        // Outgoing connection established
        submit_event(skops, EVENT_TCP_CONNECT, 0);
        
        // Enable additional callbacks
        bpf_sock_ops_cb_flags_set(skops, 
            BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG |
            BPF_SOCK_OPS_RTO_CB_FLAG |
            BPF_SOCK_OPS_RETRANS_CB_FLAG |
            BPF_SOCK_OPS_STATE_CB_FLAG);
        break;
        
    case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
        // Incoming connection accepted
        submit_event(skops, EVENT_TCP_ACCEPT, 0);
        
        // Enable additional callbacks
        bpf_sock_ops_cb_flags_set(skops,
            BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG |
            BPF_SOCK_OPS_RTO_CB_FLAG |
            BPF_SOCK_OPS_RETRANS_CB_FLAG |
            BPF_SOCK_OPS_STATE_CB_FLAG);
        break;
        
    case BPF_SOCK_OPS_RTO_CB:
        // Retransmission timeout - indicates potential latency
        submit_event(skops, EVENT_DATA_SENT, skops->bytes_acked);
        break;
        
    case BPF_SOCK_OPS_HDR_OPT_LEN_CB:
        // Called when TCP header options are being written
        if (skops->bytes_acked > 0) {
            submit_event(skops, EVENT_DATA_SENT, skops->bytes_acked);
        }
        break;
        
    case BPF_SOCK_OPS_STATE_CB:
        // Socket state change - can track connection lifecycle
        if (skops->bytes_received > 0) {
            submit_event(skops, EVENT_DATA_RECEIVED, skops->bytes_received);
        }
        break;
    }
    
    return 0;
}

char _license[] SEC("license") = "GPL";