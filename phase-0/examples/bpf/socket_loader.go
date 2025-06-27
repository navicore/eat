// socket_loader.go - Userspace loader for socket-based eBPF audio tracer
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
	TimestampNs   uint64
	Pid           uint32
	SrcIP         uint32
	DstIP         uint32
	SrcPort       uint16
	DstPort       uint16
	IntervalID    [37]byte
	PatternType   uint8
	PatternOffset uint32
	IsIngress     uint8
	DataLen       uint32
	_             [2]byte // padding
}

// Pattern type constants (must match audio_patterns_simple.h)
const (
	PATTERN_NONE    = 0
	PATTERN_SILENCE = 1
	PATTERN_SOUND   = 2
)

var patternNames = map[uint8]string{
	PATTERN_NONE:    "none",
	PATTERN_SILENCE: "silence",
	PATTERN_SOUND:   "sound",
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
	spec, err := ebpf.LoadCollectionSpec("socket_audio_tracer.o")
	if err != nil {
		return fmt.Errorf("failed to load eBPF spec: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("failed to create collection: %w", err)
	}
	defer coll.Close()

	// Attach sockops program
	sockOps := coll.Programs["sock_ops_tracer"]
	if sockOps == nil {
		return fmt.Errorf("sockops program not found")
	}

	sockOpsLink, err := link.AttachCgroup(link.CgroupOptions{
		Path:    "/sys/fs/cgroup",
		Program: sockOps,
		Attach:  ebpf.AttachCGroupSockOps,
	})
	if err != nil {
		return fmt.Errorf("failed to attach sockops: %w", err)
	}
	defer sockOpsLink.Close()

	log.Println("Attached sockops program")

	// Attach sk_msg program
	msgProg := coll.Programs["msg_tracer"]
	if msgProg == nil {
		return fmt.Errorf("sk_msg program not found")
	}

	// Create sockmap for sk_msg
	sockMapSpec := &ebpf.MapSpec{
		Type:       ebpf.MapType(15), // BPF_MAP_TYPE_SOCKMAP
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 10000,
	}
	
	sockMap, err := ebpf.NewMap(sockMapSpec)
	if err != nil {
		return fmt.Errorf("failed to create sockmap: %w", err)
	}
	defer sockMap.Close()

	// Attach sk_msg to sockmap
	if err := sockMap.Update(uint32(0), msgProg, ebpf.UpdateAny); err != nil {
		log.Printf("Warning: failed to attach sk_msg (this is expected in some environments): %v", err)
		// Continue anyway - sockops will still work
	}

	// Open output CSV file
	outputFile, err := os.Create("/output/socket_trace.csv")
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer outputFile.Close()

	csvWriter := csv.NewWriter(outputFile)
	defer csvWriter.Flush()

	// Write header
	csvWriter.Write([]string{
		"timestamp_ns", "pid", "src_ip", "src_port", "dst_ip", "dst_port",
		"direction", "pattern_type", "pattern_offset", "data_len",
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
	var totalEvents, silencePatterns uint64
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

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

			totalEvents++

			// Convert IPs
			srcIP := intToIP(event.SrcIP)
			dstIP := intToIP(event.DstIP)

			// Determine direction
			direction := "unknown"
			if event.IsIngress > 0 {
				direction = "ingress"
			} else {
				direction = "egress"
			}

			// Get pattern name
			patternName := patternNames[event.PatternType]
			if event.PatternType == PATTERN_SILENCE {
				silencePatterns++
			}

			// Write to CSV
			csvWriter.Write([]string{
				fmt.Sprintf("%d", event.TimestampNs),
				fmt.Sprintf("%d", event.Pid),
				srcIP, fmt.Sprintf("%d", event.SrcPort),
				dstIP, fmt.Sprintf("%d", event.DstPort),
				direction,
				patternName, fmt.Sprintf("%d", event.PatternOffset),
				fmt.Sprintf("%d", event.DataLen),
			})
			csvWriter.Flush()

			// Log interesting events
			if event.PatternType > 0 {
				log.Printf("PATTERN: PID=%d %s:%d -> %s:%d %s pattern=%s offset=%d len=%d",
					event.Pid, srcIP, event.SrcPort, dstIP, event.DstPort,
					direction, patternName, event.PatternOffset, event.DataLen)
			} else if totalEvents <= 10 {
				// Debug first few events
				log.Printf("DEBUG: PID=%d %s:%d -> %s:%d %s len=%d",
					event.Pid, srcIP, event.SrcPort, dstIP, event.DstPort,
					direction, event.DataLen)
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
			if totalEvents > 0 {
				log.Printf("Socket events: %d, Silence patterns detected: %d",
					totalEvents, silencePatterns)
			}
		}
	}
}

func intToIP(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", ip&0xff, (ip>>8)&0xff, (ip>>16)&0xff, (ip>>24)&0xff)
}