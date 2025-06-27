#!/bin/bash
# pod_interface_tracer.sh - Attach eBPF to pod network interfaces

set -e

echo "=== Finding pod network interfaces ==="

# Get all network interfaces in the cni namespace
INTERFACES=$(ip link show | grep -E "veth|cali" | awk -F: '{print $2}' | tr -d ' ')

if [ -z "$INTERFACES" ]; then
    echo "No pod interfaces found"
    exit 1
fi

echo "Found interfaces:"
echo "$INTERFACES"

# Load eBPF program
echo -e "\n=== Loading TC eBPF program ==="

# Compile if needed
if [ ! -f "/app/tc_audio_tracer.o" ]; then
    echo "Compiling TC eBPF program..."
    clang-14 -O2 -g -target bpf \
        -D__TARGET_ARCH_x86 \
        -I/usr/include/x86_64-linux-gnu \
        -I/usr/include \
        -c tc_audio_tracer.c -o tc_audio_tracer.o
fi

# Attach to each interface
for IFACE in $INTERFACES; do
    echo -e "\nAttaching to interface: $IFACE"
    
    # Remove existing qdiscs
    tc qdisc del dev $IFACE clsact 2>/dev/null || true
    
    # Add clsact qdisc
    tc qdisc add dev $IFACE clsact
    
    # Attach ingress filter
    tc filter add dev $IFACE ingress bpf da obj tc_audio_tracer.o sec tc/ingress
    
    # Attach egress filter  
    tc filter add dev $IFACE egress bpf da obj tc_audio_tracer.o sec tc/egress
    
    echo "Attached to $IFACE"
done

echo -e "\n=== Starting userspace loader ==="
exec /app/tc_loader