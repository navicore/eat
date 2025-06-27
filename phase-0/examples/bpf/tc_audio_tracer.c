// tc_audio_tracer.c - TC-based eBPF program for audio pattern detection
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "audio_patterns_simple.h"

// Constants
#define AUDIO_PORT_SOURCE 8000
#define AUDIO_PORT_RELAY 8001
#define INTERVAL_ID_LEN 36

// Event structure for userspace
struct audio_event {
    __u64 timestamp_ns;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 pattern_type;   // Audio pattern detected
    __u32 pattern_offset; // Where in data
    __u8 is_ingress;     // 1 for incoming, 0 for outgoing
    __u32 data_len;      // Length of data processed
    __u8 _pad[3];
};

// Map for sending events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256KB buffer
} events SEC(".maps");

// Count map for debugging
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} packet_count SEC(".maps");

static __always_inline int process_packet(struct __sk_buff *skb, int is_ingress) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    
    // Update packet counter
    __u32 key = 0;
    __u64 *count = bpf_map_lookup_elem(&packet_count, &key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    }
    
    // Parse Ethernet header
    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return TC_ACT_OK;
    
    // Only process IPv4
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;
    
    // Parse IP header
    struct iphdr *ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return TC_ACT_OK;
    
    // Only process TCP
    if (ip->protocol != IPPROTO_TCP)
        return TC_ACT_OK;
    
    // Parse TCP header
    __u32 ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(*ip))
        return TC_ACT_OK;
        
    struct tcphdr *tcp = data + sizeof(*eth) + ip_hdr_len;
    if (data + sizeof(*eth) + ip_hdr_len + sizeof(*tcp) > data_end)
        return TC_ACT_OK;
    
    // Extract ports
    __u16 src_port = bpf_ntohs(tcp->source);
    __u16 dst_port = bpf_ntohs(tcp->dest);
    
    // Only process audio service ports
    if (src_port != AUDIO_PORT_SOURCE && src_port != AUDIO_PORT_RELAY &&
        dst_port != AUDIO_PORT_SOURCE && dst_port != AUDIO_PORT_RELAY)
        return TC_ACT_OK;
    
    // Calculate TCP data offset
    __u32 tcp_hdr_len = tcp->doff * 4;
    if (tcp_hdr_len < sizeof(*tcp))
        return TC_ACT_OK;
        
    void *payload = data + sizeof(*eth) + ip_hdr_len + tcp_hdr_len;
    __u32 payload_len = bpf_ntohs(ip->tot_len) - ip_hdr_len - tcp_hdr_len;
    
    // Skip if no payload
    if (payload_len < 100 || payload + 100 > data_end)
        return TC_ACT_OK;
    
    // Create event
    struct audio_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return TC_ACT_OK;
    
    __builtin_memset(event, 0, sizeof(*event));
    event->timestamp_ns = bpf_ktime_get_ns();
    event->src_ip = bpf_ntohl(ip->saddr);
    event->dst_ip = bpf_ntohl(ip->daddr);
    event->src_port = src_port;
    event->dst_port = dst_port;
    event->is_ingress = is_ingress;
    event->data_len = payload_len;
    
    // Try to find silence pattern
    #pragma unroll
    for (int i = 0; i < 50 && i < payload_len - 8; i += 8) {
        if (payload + i + 8 > data_end)
            break;
            
        if (check_for_silence(payload + i, data_end)) {
            event->pattern_type = PATTERN_SILENCE;
            event->pattern_offset = i;
            break;
        }
    }
    
    bpf_ringbuf_submit(event, 0);
    
    return TC_ACT_OK;
}

SEC("tc/ingress")
int tc_ingress(struct __sk_buff *skb) {
    return process_packet(skb, 1);
}

SEC("tc/egress")
int tc_egress(struct __sk_buff *skb) {
    return process_packet(skb, 0);
}

char _license[] SEC("license") = "GPL";