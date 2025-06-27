#!/bin/bash
# pod_netns_tracer.sh - Trace directly in pod network namespaces

set -e

echo "=== Pod Network Namespace Tracer ==="

# Find all network namespaces
NAMESPACES=$(ls /var/run/netns/ 2>/dev/null || echo "")

if [ -z "$NAMESPACES" ]; then
    echo "No network namespaces found in /var/run/netns/"
    echo "Looking for pod interfaces directly..."
    
    # Find veth interfaces (pod interfaces)
    VETHS=$(ip link show | grep -E "veth|cali" | awk -F: '{print $2}' | tr -d ' ')
    
    if [ -z "$VETHS" ]; then
        echo "No pod interfaces found"
        exit 1
    fi
    
    echo "Found veth interfaces:"
    echo "$VETHS"
    
    # Attach TC to each veth interface
    for VETH in $VETHS; do
        echo -e "\nAttaching to $VETH..."
        
        # Skip if interface doesn't exist
        if ! ip link show $VETH > /dev/null 2>&1; then
            continue
        fi
        
        # Remove existing qdiscs
        tc qdisc del dev $VETH clsact 2>/dev/null || true
        
        # Add clsact qdisc
        tc qdisc add dev $VETH clsact
        
        # Load TC program
        tc filter add dev $VETH ingress bpf da obj tc_audio_tracer.o sec tc/ingress
        tc filter add dev $VETH egress bpf da obj tc_audio_tracer.o sec tc/egress
        
        echo "Attached to $VETH"
    done
else
    echo "Found network namespaces:"
    echo "$NAMESPACES"
    
    # Process each namespace
    for NS in $NAMESPACES; do
        echo -e "\nProcessing namespace: $NS"
        
        # List interfaces in namespace
        IFACES=$(ip netns exec $NS ip link show | grep -E "^[0-9]+:" | grep -v "lo:" | awk -F: '{print $2}' | tr -d ' ')
        
        for IFACE in $IFACES; do
            echo "Attaching to $IFACE in namespace $NS..."
            
            # Remove existing qdiscs
            ip netns exec $NS tc qdisc del dev $IFACE clsact 2>/dev/null || true
            
            # Add clsact qdisc
            ip netns exec $NS tc qdisc add dev $IFACE clsact
            
            # Load TC program
            ip netns exec $NS tc filter add dev $IFACE ingress bpf da obj tc_audio_tracer.o sec tc/ingress
            ip netns exec $NS tc filter add dev $IFACE egress bpf da obj tc_audio_tracer.o sec tc/egress
            
            echo "Attached to $IFACE"
        done
    done
fi

echo -e "\n=== Starting userspace loader ==="
exec /app/tc_loader