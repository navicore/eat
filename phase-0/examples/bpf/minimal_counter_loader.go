// minimal_counter_loader.go - Simple loader that just prints packet counts
package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("Error: %v", err)
	}
}

func findInterfaces() []string {
	// Find all veth interfaces (pod interfaces)
	out, err := exec.Command("ip", "link", "show").Output()
	if err != nil {
		log.Printf("Failed to list interfaces: %v", err)
		return nil
	}
	
	var interfaces []string
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		if strings.Contains(line, "veth") || strings.Contains(line, "eth0") {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				iface := strings.TrimSpace(parts[1])
				if strings.Contains(iface, "@") {
					iface = strings.Split(iface, "@")[0]
				}
				interfaces = append(interfaces, iface)
			}
		}
	}
	return interfaces
}

func attachTC(iface string) error {
	log.Printf("Attaching to interface: %s", iface)
	
	// Remove existing qdisc (ignore errors)
	exec.Command("tc", "qdisc", "del", "dev", iface, "clsact").Run()
	
	// Add clsact qdisc
	cmd := exec.Command("tc", "qdisc", "add", "dev", iface, "clsact")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add clsact: %w", err)
	}
	
	// Attach TC program to ingress
	cmd = exec.Command("tc", "filter", "add", "dev", iface, "ingress",
		"bpf", "da", "obj", "minimal_tcp_counter.o", "sec", "tc")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to attach ingress: %w", err)
	}
	
	// Attach TC program to egress
	cmd = exec.Command("tc", "filter", "add", "dev", iface, "egress",
		"bpf", "da", "obj", "minimal_tcp_counter.o", "sec", "tc")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to attach egress: %w", err)
	}
	
	return nil
}

func run() error {
	// Remove memory limit for eBPF
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("failed to remove memlock: %w", err)
	}

	// Find interfaces to attach to
	interfaces := findInterfaces()
	if len(interfaces) == 0 {
		return fmt.Errorf("no interfaces found")
	}
	
	log.Printf("Found %d interfaces: %v", len(interfaces), interfaces)
	
	// Attach to each interface
	attached := 0
	for _, iface := range interfaces {
		if err := attachTC(iface); err != nil {
			log.Printf("Warning: failed to attach to %s: %v", iface, err)
		} else {
			attached++
		}
	}
	
	if attached == 0 {
		return fmt.Errorf("failed to attach to any interface")
	}
	
	log.Printf("Successfully attached to %d interfaces", attached)
	
	// Load the BPF object to access maps
	spec, err := ebpf.LoadCollectionSpec("minimal_tcp_counter.o")
	if err != nil {
		return fmt.Errorf("failed to load spec: %w", err)
	}
	
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("failed to create collection: %w", err)
	}
	defer coll.Close()
	
	// Get counter map
	counters := coll.Maps["counters"]
	if counters == nil {
		return fmt.Errorf("counters map not found")
	}
	
	// Handle signals
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	
	// Print counters every 2 seconds
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	
	log.Println("Monitoring packets... Press Ctrl+C to stop")
	log.Println("Counters: TOTAL | TCP | HTTP (ports 80,8000,8001,30080,30081)")
	
	for {
		select {
		case <-sig:
			log.Println("Exiting...")
			return nil
		case <-ticker.C:
			// Read counters
			var total, tcp, http uint64
			
			// Get total packets
			var key uint32 = 0
			var values []uint64
			if err := counters.Lookup(&key, &values); err == nil && len(values) > 0 {
				for _, v := range values {
					total += v
				}
			}
			
			// Get TCP packets
			key = 1
			values = nil
			if err := counters.Lookup(&key, &values); err == nil && len(values) > 0 {
				for _, v := range values {
					tcp += v
				}
			}
			
			// Get HTTP packets
			key = 2
			values = nil
			if err := counters.Lookup(&key, &values); err == nil && len(values) > 0 {
				for _, v := range values {
					http += v
				}
			}
			
			fmt.Printf("Packets: %d | %d | %d\n", total, tcp, http)
		}
	}
}