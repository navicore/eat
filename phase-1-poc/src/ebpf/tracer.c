#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/sched.h> // For bpf_get_current_pid_tgid
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// Define the event structure (though we're using a map, this helps define the data)
struct event {
    __u32 pid;
    __u64 timestamp_ns;
    __u64 signature;
};

// Define a hash map to store signatures
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __uint(key_size, sizeof(__u32)); // PID
    __uint(value_size, sizeof(__u64)); // Signature
} signatures SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} config_map SEC(".maps");


SEC("tracepoint/syscalls/sys_enter_write")
int tracepoint__syscalls__sys_enter_write(struct trace_event_raw_sys_enter* ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 key = 0;
    __u32* target_pid = bpf_map_lookup_elem(&config_map, &key);

    if (!target_pid || *target_pid != pid) {
        return 0;
    }

    __u64 timestamp_ns = bpf_ktime_get_ns();

    // Dummy signature for now
    __u64 signature = 0xDEADBEEF;

    bpf_printk("eBPF: write() called by PID %d, Signature: %llx", pid, signature);

    // Store the signature in the map
    bpf_map_update_elem(&signatures, &pid, &signature, BPF_ANY);

    return 0;
}

char _license[] SEC("license") = "GPL";
