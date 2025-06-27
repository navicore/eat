// socket_audio_tracer.c - Socket-based eBPF program for audio pattern detection
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "audio_patterns_simple.h"

// Constants
#define AUDIO_PORT_SOURCE 8000
#define AUDIO_PORT_RELAY 8001
#define MAX_MSG_SIZE 4096
#define INTERVAL_ID_LEN 36

// Event structure for userspace
struct audio_event {
    __u64 timestamp_ns;
    __u32 pid;           // Process ID
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    char interval_id[INTERVAL_ID_LEN + 1];
    __u8 pattern_type;   // Audio pattern detected
    __u32 pattern_offset; // Where in data
    __u8 is_ingress;     // 1 for incoming, 0 for outgoing
    __u32 data_len;      // Length of data processed
};

// Map for sending events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256KB buffer
} events SEC(".maps");

// Map to track socket info
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u64);   // Socket pointer
    __type(value, struct sock_info);
} socket_info SEC(".maps");

struct sock_info {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
};

// Helper to extract socket info
static __always_inline void extract_sock_info(struct bpf_sock_ops *skops, struct sock_info *info) {
    info->src_ip = skops->local_ip4;
    info->dst_ip = skops->remote_ip4;
    info->src_port = bpf_ntohs(skops->local_port);
    info->dst_port = skops->remote_port;
}

// Socket operations program - tracks TCP connections
SEC("sockops")
int sock_ops_tracer(struct bpf_sock_ops *skops) {
    __u32 op = skops->op;
    __u16 local_port = bpf_ntohs(skops->local_port);
    __u16 remote_port = skops->remote_port;
    
    // Only track audio service ports
    if (local_port != AUDIO_PORT_SOURCE && local_port != AUDIO_PORT_RELAY &&
        remote_port != AUDIO_PORT_SOURCE && remote_port != AUDIO_PORT_RELAY)
        return 0;
    
    // Track connection establishment
    if (op == BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB || 
        op == BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB) {
        
        struct sock_info info = {};
        extract_sock_info(skops, &info);
        
        __u64 sock_key = (__u64)skops->sk;
        bpf_map_update_elem(&socket_info, &sock_key, &info, BPF_ANY);
        
        // Enable callbacks for data
        bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG);
    }
    
    return 0;
}

// SK_MSG program - analyzes message data
SEC("sk_msg")
int msg_tracer(struct sk_msg_md *msg) {
    __u32 data_len = msg->data_end - msg->data;
    if (data_len < 100) // Skip small messages
        return SK_PASS;
    
    // Get socket info - use sk as a pointer value
    __u64 sk_key = (__u64)msg->sk;
    struct sock_info *info = bpf_map_lookup_elem(&socket_info, &sk_key);
    if (!info)
        return SK_PASS;
    
    // Only process audio ports
    if (info->src_port != AUDIO_PORT_SOURCE && info->src_port != AUDIO_PORT_RELAY &&
        info->dst_port != AUDIO_PORT_SOURCE && info->dst_port != AUDIO_PORT_RELAY)
        return SK_PASS;
    
    // Reserve space for event
    struct audio_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return SK_PASS;
    
    // Initialize event
    __builtin_memset(event, 0, sizeof(*event));
    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->src_ip = info->src_ip;
    event->dst_ip = info->dst_ip;
    event->src_port = info->src_port;
    event->dst_port = info->dst_port;
    event->data_len = data_len;
    event->is_ingress = (info->dst_port == AUDIO_PORT_SOURCE || info->dst_port == AUDIO_PORT_RELAY) ? 1 : 0;
    
    // Try to find audio patterns in the message data
    void *data = (void *)(long)msg->data;
    void *data_end = (void *)(long)msg->data_end;
    
    // Search for silence pattern in first 200 bytes
    #pragma unroll
    for (int i = 0; i < 200; i += 8) {
        if (data + i + 8 > data_end)
            break;
            
        if (check_for_silence(data + i, data_end)) {
            event->pattern_type = PATTERN_SILENCE;
            event->pattern_offset = i;
            break;
        }
    }
    
    // Always submit event for debugging
    bpf_ringbuf_submit(event, 0);
    
    return SK_PASS;
}

char _license[] SEC("license") = "GPL";