#!/bin/bash

set -e

echo "Building project..."
cargo build --release

echo "Starting sink on port 8081..."
./target/release/audio-test-client sink -l 127.0.0.1:8081 &
SINK_PID=$!

echo "Starting relay from 8080 to 8081..."
./target/release/audio-test-client relay -l 127.0.0.1:8080 -f 127.0.0.1:8081 &
RELAY_PID=$!

echo "Waiting for services to start..."
sleep 2

echo "Starting eBPF tracker (requires sudo)..."
echo "Run this in another terminal:"
echo "sudo ./target/release/audio-latency -i lo"
echo ""
echo "Press Enter when tracker is running..."
read

echo "Sending test audio patterns..."
./target/release/audio-test-client send -t 127.0.0.1:8080 -c 5 -i 500

echo "Test complete. Cleaning up..."
kill $SINK_PID $RELAY_PID 2>/dev/null || true

echo "Check the eBPF tracker output for latency measurements!"