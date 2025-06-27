#!/bin/bash
# test_ebpf.sh - Test if eBPF is working at all

set -e

echo "=== Testing eBPF capabilities ==="

# Check kernel version
echo "Kernel version:"
uname -r

# Check if BPF syscall is available
echo -e "\nChecking BPF syscall..."
if grep -q "CONFIG_BPF_SYSCALL=y" /boot/config-$(uname -r) 2>/dev/null; then
    echo "BPF syscall: ENABLED"
else
    echo "BPF syscall: UNKNOWN (config not accessible)"
fi

# Check cgroup type
echo -e "\nCgroup type:"
if [ -f /sys/fs/cgroup/cgroup.controllers ]; then
    echo "cgroup v2"
else
    echo "cgroup v1"
fi

# Test loading a minimal BPF program
echo -e "\nCreating minimal test program..."
cat > /tmp/test_minimal.c << 'EOF'
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int test_prog(struct xdp_md *ctx) {
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
EOF

# Try to compile
echo "Compiling test program..."
if clang-14 -O2 -g -target bpf -c /tmp/test_minimal.c -o /tmp/test_minimal.o 2>/dev/null; then
    echo "Compilation: SUCCESS"
    
    # Try to load with ip link
    echo -e "\nTrying to attach to lo interface..."
    if ip link set dev lo xdp obj /tmp/test_minimal.o sec xdp 2>/dev/null; then
        echo "XDP attach: SUCCESS"
        ip link set dev lo xdp off
    else
        echo "XDP attach: FAILED"
    fi
else
    echo "Compilation: FAILED"
fi

# Check for veth interfaces
echo -e "\nVeth interfaces found:"
ip link show type veth 2>/dev/null | grep -E "^[0-9]+:" | awk '{print $2}' | tr -d ':' || echo "None"

# Check TC capabilities
echo -e "\nTC capabilities:"
tc qdisc show | head -5 || echo "TC not available"

echo -e "\n=== Test complete ==="