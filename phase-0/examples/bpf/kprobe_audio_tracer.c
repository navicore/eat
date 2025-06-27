// kprobe_audio_tracer.c - Kprobe-based socket tracer
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/socket.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define AUDIO_PORT_SOURCE 8000
#define AUDIO_PORT_RELAY 8001

struct socket_event {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 tgid;
    __u16 port;
    __u8 op; // 1=bind, 2=connect, 3=accept, 4=send, 5=recv
    __u64 bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Trace bind() calls
SEC("kprobe/sys_bind")
int trace_bind(struct pt_regs *ctx) {
    struct sockaddr_in *addr = (struct sockaddr_in *)PT_REGS_PARM2(ctx);
    __u16 port;
    
    bpf_probe_read_user(&port, sizeof(port), &addr->sin_port);
    port = bpf_ntohs(port);
    
    if (port != AUDIO_PORT_SOURCE && port != AUDIO_PORT_RELAY)
        return 0;
    
    struct socket_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;
    
    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    e->tgid = bpf_get_current_pid_tgid() >> 32;
    e->port = port;
    e->op = 1; // bind
    e->bytes = 0;
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Trace sendto/sendmsg calls
SEC("kprobe/sys_sendto")
int trace_sendto(struct pt_regs *ctx) {
    size_t len = (size_t)PT_REGS_PARM3(ctx);
    
    struct socket_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;
    
    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    e->tgid = bpf_get_current_pid_tgid() >> 32;
    e->port = 0; // Would need to track socket to port mapping
    e->op = 4; // send
    e->bytes = len;
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";