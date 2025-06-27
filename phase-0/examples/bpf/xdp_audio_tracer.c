// xdp_audio_tracer.c - XDP-based eBPF program for audio pattern detection
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "audio_patterns_simple.h"

// Constants
#define AUDIO_PORT_SOURCE 8000
#define AUDIO_PORT_RELAY 8001

// Event structure for userspace
struct audio_event {
    __u64 timestamp_ns;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 pattern_type;   // Audio pattern detected
    __u32 pattern_offset; // Where in data
    __u32 data_len;      // Length of data processed
    __u32 pkt_count;     // Debug: packet counter
};

// Map for sending events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256KB buffer
} events SEC(".maps");

// Packet counter for debugging
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} pkt_count SEC(".maps");

SEC("xdp")
int xdp_audio_tracer(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    // Update packet counter
    __u32 key = 0;
    __u64 *count = bpf_map_lookup_elem(&pkt_count, &key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    }
    
    // Parse Ethernet header
    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;
    
    // Only process IPv4
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;
    
    // Parse IP header
    struct iphdr *ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return XDP_PASS;
    
    // Only process TCP
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;
    
    // Parse TCP header
    __u32 ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(*ip))
        return XDP_PASS;
        
    struct tcphdr *tcp = data + sizeof(*eth) + ip_hdr_len;
    if (data + sizeof(*eth) + ip_hdr_len + sizeof(*tcp) > data_end)
        return XDP_PASS;
    
    // Extract ports
    __u16 src_port = bpf_ntohs(tcp->source);
    __u16 dst_port = bpf_ntohs(tcp->dest);
    
    // Only process audio service ports
    if (src_port != AUDIO_PORT_SOURCE && src_port != AUDIO_PORT_RELAY &&
        dst_port != AUDIO_PORT_SOURCE && dst_port != AUDIO_PORT_RELAY)
        return XDP_PASS;
    
    // Calculate TCP data offset
    __u32 tcp_hdr_len = tcp->doff * 4;
    if (tcp_hdr_len < sizeof(*tcp))
        return XDP_PASS;
        
    void *payload = data + sizeof(*eth) + ip_hdr_len + tcp_hdr_len;
    __u32 payload_len = bpf_ntohs(ip->tot_len) - ip_hdr_len - tcp_hdr_len;
    
    // Skip if no significant payload
    if (payload_len < 50 || payload + 50 > data_end)
        return XDP_PASS;
    
    // Create event
    struct audio_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return XDP_PASS;
    
    __builtin_memset(event, 0, sizeof(*event));
    event->timestamp_ns = bpf_ktime_get_ns();
    event->src_ip = bpf_ntohl(ip->saddr);
    event->dst_ip = bpf_ntohl(ip->daddr);
    event->src_port = src_port;
    event->dst_port = dst_port;
    event->data_len = payload_len;
    
    // Get packet count for debugging
    if (count) {
        event->pkt_count = *count;
    }
    
    // Try to find silence pattern in first 40 bytes
    #pragma unroll
    for (int i = 0; i < 40 && i < payload_len - 8; i += 8) {
        if (payload + i + 8 > data_end)
            break;
            
        if (check_for_silence(payload + i, data_end)) {
            event->pattern_type = PATTERN_SILENCE;
            event->pattern_offset = i;
            break;
        }
    }
    
    bpf_ringbuf_submit(event, 0);
    
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";