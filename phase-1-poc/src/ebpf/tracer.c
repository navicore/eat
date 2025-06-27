// Placeholder for eBPF C code
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// Basic tracepoint for sys_enter_write
SEC("tracepoint/syscalls/sys_enter_write")
int tracepoint__syscalls__sys_enter_write(struct trace_event_raw_sys_enter* ctx) {
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));
    bpf_printk("process %s called write()", comm);
    return 0;
}

char _license[] SEC("license") = "GPL";
