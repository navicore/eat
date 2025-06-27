// super_minimal.c - Absolute minimal eBPF that just counts packets
#include <linux/bpf.h>
#include <linux/pkt_cls.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
} counter SEC(".maps");

SEC("tc")
int count_all(struct __sk_buff *skb) {
    __u32 key = 0;
    __u64 *value;
    
    value = bpf_map_lookup_elem(&counter, &key);
    if (value) {
        __sync_fetch_and_add(value, 1);
    }
    
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";