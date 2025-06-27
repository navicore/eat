#!/bin/bash
# cni_bridge_finder.sh - Find and attach XDP to CNI bridge interface

set -e

echo "=== Finding CNI bridge interface ==="

# Common CNI bridge names
BRIDGE_PATTERNS="cni0|docker0|weave|flannel|kube-bridge|kindnet-bridge|br-"

# Find the bridge interface
BRIDGE=$(ip link show | grep -E "$BRIDGE_PATTERNS" | head -1 | awk -F: '{print $2}' | tr -d ' ')

if [ -z "$BRIDGE" ]; then
    echo "No CNI bridge found, looking for Kind interfaces..."
    # In Kind, sometimes it's just br-xxxx
    BRIDGE=$(ip link show | grep "br-" | head -1 | awk -F: '{print $2}' | tr -d ' ')
fi

if [ -z "$BRIDGE" ]; then
    echo "ERROR: No bridge interface found"
    echo "Available interfaces:"
    ip link show | awk -F: '{print $2}' | tr -d ' '
    exit 1
fi

echo "Found bridge interface: $BRIDGE"

# Get bridge details
echo -e "\nBridge details:"
ip addr show $BRIDGE

# Compile XDP program if needed
if [ ! -f "/app/xdp_audio_tracer.o" ]; then
    echo -e "\nCompiling XDP program..."
    clang-14 -O2 -g -target bpf \
        -D__TARGET_ARCH_$(uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/') \
        -I/usr/include/$(uname -m)-linux-gnu \
        -I/usr/include \
        -c xdp_audio_tracer.c -o xdp_audio_tracer.o
fi

# Detach any existing XDP program
echo -e "\nDetaching existing XDP programs..."
ip link set dev $BRIDGE xdp off 2>/dev/null || true

# Attach XDP program
echo "Attaching XDP program to $BRIDGE..."
ip link set dev $BRIDGE xdp obj xdp_audio_tracer.o sec xdp

echo "XDP program attached successfully"

# Start userspace loader
echo -e "\n=== Starting userspace loader ==="
exec /app/xdp_loader