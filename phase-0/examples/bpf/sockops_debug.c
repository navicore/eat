// sockops_debug.c - Debug version that logs all TCP events
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Debug event structure
struct debug_event {
    __u64 timestamp_ns;
    __u32 op;            // Operation type
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u32 bytes_acked;
    __u32 bytes_received;
};

// Map for sending events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256KB buffer
} events SEC(".maps");

// Counter map
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} call_count SEC(".maps");

SEC("sockops")
int sockops_debug(struct bpf_sock_ops *skops) {
    __u32 op = skops->op;
    
    // Count all calls
    __u32 key = 0;
    __u64 *count = bpf_map_lookup_elem(&call_count, &key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    }
    
    // Log all TCP events
    struct debug_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;
    
    __builtin_memset(event, 0, sizeof(*event));
    event->timestamp_ns = bpf_ktime_get_ns();
    event->op = op;
    event->src_ip = skops->local_ip4;
    event->dst_ip = skops->remote_ip4;
    event->src_port = bpf_ntohs(skops->local_port);
    event->dst_port = skops->remote_port;
    event->bytes_acked = skops->bytes_acked;
    event->bytes_received = skops->bytes_received;
    
    bpf_ringbuf_submit(event, 0);
    
    // Enable callbacks for established connections
    if (op == BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB || 
        op == BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB) {
        bpf_sock_ops_cb_flags_set(skops, 
            BPF_SOCK_OPS_STATE_CB_FLAG |
            BPF_SOCK_OPS_RTO_CB_FLAG);
    }
    
    return 0;
}

char _license[] SEC("license") = "GPL";