// minimal_tcp_counter.c - Simplest possible eBPF to count TCP packets
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Simple counter map - just count packets
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 3);
    __type(key, __u32);
    __type(value, __u64);
} counters SEC(".maps");

// Counter indices
#define TOTAL_PACKETS 0
#define TCP_PACKETS   1
#define HTTP_PACKETS  2

SEC("tc")
int count_packets(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    
    // Count total packets
    __u32 key = TOTAL_PACKETS;
    __u64 *total_count = bpf_map_lookup_elem(&counters, &key);
    if (total_count) {
        __sync_fetch_and_add(total_count, 1);
    }
    
    // Parse Ethernet header
    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return TC_ACT_OK;
    
    // Only IPv4
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;
    
    // Parse IP header
    struct iphdr *ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return TC_ACT_OK;
    
    // Count TCP packets
    if (ip->protocol == IPPROTO_TCP) {
        key = TCP_PACKETS;
        __u64 *tcp_count = bpf_map_lookup_elem(&counters, &key);
        if (tcp_count) {
            __sync_fetch_and_add(tcp_count, 1);
        }
        
        // Check if it's HTTP (port 80, 8000, 8001, etc)
        __u32 ip_hdr_len = ip->ihl * 4;
        struct tcphdr *tcp = data + sizeof(*eth) + ip_hdr_len;
        if (data + sizeof(*eth) + ip_hdr_len + sizeof(*tcp) > data_end)
            return TC_ACT_OK;
            
        __u16 dst_port = bpf_ntohs(tcp->dest);
        if (dst_port == 80 || dst_port == 8000 || dst_port == 8001 || 
            dst_port == 30080 || dst_port == 30081) {
            key = HTTP_PACKETS;
            __u64 *http_count = bpf_map_lookup_elem(&counters, &key);
            if (http_count) {
                __sync_fetch_and_add(http_count, 1);
            }
        }
    }
    
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";