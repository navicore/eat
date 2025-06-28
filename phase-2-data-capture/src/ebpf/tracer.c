#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define DATA_SIZE 64

struct event {
    __u32 pid;
    char data[DATA_SIZE];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} config_map SEC(".maps");


SEC("raw_tracepoint/sys_enter")
int raw_tracepoint__sys_enter(struct bpf_raw_tracepoint_args *ctx) {
    if (ctx->args[1] != 1) { // 1 is the syscall number for write
        return 0;
    }

    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 key = 0;
    __u32* target_pid = bpf_map_lookup_elem(&config_map, &key);

    if (!target_pid || *target_pid != pid) {
        return 0;
    }

    struct event event = {};
    event.pid = pid;

    // Read the data from the write syscall
    bpf_probe_read_user(&event.data, sizeof(event.data), (void*)ctx->args[2]);

    // Send the event to userspace
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return 0;
}

char _license[] SEC("license") = "GPL";
