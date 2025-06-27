// sockops_loader.go - Userspace loader for sockops-based eBPF audio tracer
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// Must match the C structure
type AudioEvent struct {
	TimestampNs uint64
	Pid         uint32
	SrcIP       uint32
	DstIP       uint32
	SrcPort     uint16
	DstPort     uint16
	EventType   uint8
	Bytes       uint32
	DurationNs  uint32
	_           [3]byte // padding
}

// Event type constants
const (
	EVENT_TCP_CONNECT   = 1
	EVENT_TCP_ACCEPT    = 2
	EVENT_DATA_SENT     = 3
	EVENT_DATA_RECEIVED = 4
)

var eventNames = map[uint8]string{
	EVENT_TCP_CONNECT:   "tcp_connect",
	EVENT_TCP_ACCEPT:    "tcp_accept",
	EVENT_DATA_SENT:     "data_sent",
	EVENT_DATA_RECEIVED: "data_received",
}

func main() {
	if err := run(); err != nil {
		log.Fatalf("Error: %v", err)
	}
}

func run() error {
	// Remove memory limit for eBPF
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("failed to remove memlock: %w", err)
	}

	// Load eBPF program
	spec, err := ebpf.LoadCollectionSpec("sockops_audio_tracer.o")
	if err != nil {
		return fmt.Errorf("failed to load eBPF spec: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("failed to create collection: %w", err)
	}
	defer coll.Close()

	// Attach sockops program
	sockOps := coll.Programs["sockops_audio_tracer"]
	if sockOps == nil {
		return fmt.Errorf("sockops program not found")
	}

	// Try multiple cgroup paths for better compatibility
	cgroupPaths := []string{
		"/sys/fs/cgroup",           // Standard cgroup v2 path
		"/sys/fs/cgroup/unified",   // Alternative cgroup v2 path
		"/sys/fs/cgroup/system.slice", // System slice (contains pods)
		"/sys/fs/cgroup/kubelet.slice", // Kubelet managed cgroups
	}
	
	var cgroupPath string
	
	// Try each path until one works
	for _, path := range cgroupPaths {
		if _, err := os.Stat(path); err != nil {
			continue
		}
		cgroupPath = path
		break
	}
	
	if cgroupPath == "" {
		cgroupPath = "/sys/fs/cgroup" // Fallback
	}

	sockOpsLink, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Program: sockOps,
		Attach:  ebpf.AttachCGroupSockOps,
	})
	if err != nil {
		return fmt.Errorf("failed to attach sockops to %s: %w", cgroupPath, err)
	}
	defer sockOpsLink.Close()

	log.Printf("Attached sockops program to cgroup at %s", cgroupPath)

	// Open output CSV file
	outputFile, err := os.Create("/output/sockops_trace.csv")
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer outputFile.Close()

	csvWriter := csv.NewWriter(outputFile)
	defer csvWriter.Flush()

	// Write header
	csvWriter.Write([]string{
		"timestamp_ns", "pid", "src_ip", "src_port", "dst_ip", "dst_port",
		"event_type", "bytes", "rtt_us",
	})

	// Open ringbuf reader
	rd, err := ringbuf.NewReader(coll.Maps["events"])
	if err != nil {
		return fmt.Errorf("failed to create ringbuf reader: %w", err)
	}
	defer rd.Close()

	// Handle signals
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	log.Println("Listening for socket events... Press Ctrl+C to stop")

	// Stats
	var stats = make(map[string]uint64)
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	// Connection tracking
	type connKey struct {
		srcIP   string
		srcPort uint16
		dstIP   string
		dstPort uint16
	}
	connections := make(map[connKey]time.Time)

	// Read events
	go func() {
		for {
			record, err := rd.Read()
			if err != nil {
				if err == ringbuf.ErrClosed {
					return
				}
				log.Printf("Error reading ringbuf: %v", err)
				continue
			}

			// Parse event
			var event AudioEvent
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
				log.Printf("Error parsing event: %v", err)
				continue
			}

			// Convert IPs
			srcIP := intToIP(event.SrcIP)
			dstIP := intToIP(event.DstIP)

			// Get event name
			eventName := eventNames[event.EventType]
			stats[eventName]++

			// Track connections
			key := connKey{srcIP, event.SrcPort, dstIP, event.DstPort}
			if event.EventType == EVENT_TCP_CONNECT || event.EventType == EVENT_TCP_ACCEPT {
				connections[key] = time.Now()
			}

			// Convert RTT to microseconds
			rttUs := event.DurationNs / 1000

			// Write to CSV
			csvWriter.Write([]string{
				fmt.Sprintf("%d", event.TimestampNs),
				fmt.Sprintf("%d", event.Pid),
				srcIP, fmt.Sprintf("%d", event.SrcPort),
				dstIP, fmt.Sprintf("%d", event.DstPort),
				eventName,
				fmt.Sprintf("%d", event.Bytes),
				fmt.Sprintf("%d", rttUs),
			})
			csvWriter.Flush()

			// Log interesting events
			if event.EventType == EVENT_TCP_CONNECT || event.EventType == EVENT_TCP_ACCEPT {
				log.Printf("%s: PID=%d %s:%d -> %s:%d",
					eventName, event.Pid, srcIP, event.SrcPort, dstIP, event.DstPort)
			} else if event.Bytes > 1000 { // Log significant data transfers
				log.Printf("%s: %s:%d -> %s:%d bytes=%d rtt=%dus",
					eventName, srcIP, event.SrcPort, dstIP, event.DstPort,
					event.Bytes, rttUs)
			}
		}
	}()

	// Wait for signal or stats
	for {
		select {
		case <-sig:
			log.Println("Received signal, exiting...")
			return nil
		case <-ticker.C:
			if len(stats) > 0 {
				log.Printf("Stats: connections=%d, connects=%d, accepts=%d, sent=%d, received=%d",
					len(connections), stats["tcp_connect"], stats["tcp_accept"],
					stats["data_sent"], stats["data_received"])
			}
		}
	}
}

func intToIP(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", ip&0xff, (ip>>8)&0xff, (ip>>16)&0xff, (ip>>24)&0xff)
}