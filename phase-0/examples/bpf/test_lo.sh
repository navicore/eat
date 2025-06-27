#!/bin/bash
# test_lo.sh - Test if we can capture ANY packets at all

set -e

echo "=== Testing eBPF on loopback interface ==="

# Compile the minimal counter
echo "Compiling..."
clang-14 -O2 -g -target bpf \
    -I/usr/include/$(uname -m)-linux-gnu \
    -I/usr/include \
    -c minimal_tcp_counter.c -o minimal_tcp_counter.o

# Attach to loopback
echo "Attaching to lo..."
tc qdisc del dev lo clsact 2>/dev/null || true
tc qdisc add dev lo clsact
tc filter add dev lo ingress bpf da obj minimal_tcp_counter.o sec tc
tc filter add dev lo egress bpf da obj minimal_tcp_counter.o sec tc

echo "TC filter attached. Starting packet generator..."

# Generate some traffic on loopback
(while true; do 
    curl -s http://localhost:80 >/dev/null 2>&1 || true
    nc -z localhost 22 2>/dev/null || true
    sleep 0.1
done) &
PING_PID=$!

echo "Traffic generator PID: $PING_PID"

# Run the counter
echo "Starting counter..."
/app/minimal_counter_loader &
COUNTER_PID=$!

# Let it run for 10 seconds
sleep 10

# Kill both processes
kill $PING_PID 2>/dev/null || true
kill $COUNTER_PID 2>/dev/null || true

echo "Test complete"