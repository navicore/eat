#!/bin/bash
# debug-sockops.sh - Debug script for sockops attachment in Kind

echo "=== Cgroup Information ==="
echo "Cgroup type:"
if [ -f /sys/fs/cgroup/cgroup.controllers ]; then
    echo "cgroup v2 detected"
    cat /sys/fs/cgroup/cgroup.controllers
else
    echo "cgroup v1 detected"
fi

echo -e "\n=== Cgroup hierarchy ==="
ls -la /sys/fs/cgroup/

echo -e "\n=== Pod cgroups ==="
# Find audio pods
for pod in $(crictl pods --name audio- -q 2>/dev/null || docker ps --filter "label=io.kubernetes.pod.name" --format "{{.ID}}" | head -5); do
    echo "Pod: $pod"
    if command -v crictl &> /dev/null; then
        crictl inspect $pod | grep -A5 "cgroupsPath" || true
    else
        docker inspect $pod | grep -i cgroup || true
    fi
done

echo -e "\n=== Network namespaces ==="
ls -la /var/run/netns/ 2>/dev/null || echo "No network namespaces found"

echo -e "\n=== BPF programs loaded ==="
if command -v bpftool &> /dev/null; then
    bpftool prog list | grep -E "(sockops|sk_msg)" || echo "No sockops/sk_msg programs found"
else
    echo "bpftool not available"
fi

echo -e "\n=== TCP connections on audio ports ==="
ss -tan | grep -E "(8000|8001)" || echo "No connections on audio ports"

echo -e "\n=== Kernel sockops support ==="
if grep -q "CONFIG_BPF_STREAM_PARSER=y" /boot/config-$(uname -r) 2>/dev/null; then
    echo "BPF stream parser support: YES"
else
    echo "BPF stream parser support: UNKNOWN"
fi

echo -e "\n=== Checking actual service ports ==="
# Inside Kind, we can check the actual service endpoints
iptables -t nat -L KUBE-SERVICES -n 2>/dev/null | grep -E "audio|8000|8001" | head -10 || true