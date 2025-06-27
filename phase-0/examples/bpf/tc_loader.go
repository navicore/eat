// tc_loader.go - Userspace loader for TC-based eBPF audio tracer
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
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// Must match the C structure
type AudioEvent struct {
	TimestampNs   uint64
	SrcIP         uint32
	DstIP         uint32
	SrcPort       uint16
	DstPort       uint16
	PatternType   uint8
	PatternOffset uint32
	IsIngress     uint8
	DataLen       uint32
	_             [3]byte // padding
}

// Pattern type constants
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

	// Load eBPF program that was already attached by tc
	spec, err := ebpf.LoadCollectionSpec("tc_audio_tracer.o")
	if err != nil {
		return fmt.Errorf("failed to load eBPF spec: %w", err)
	}

	// We only need to access the maps (program is already attached)
	opts := ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel: ebpf.LogLevelInstruction,
			LogSize:  64 * 1024,
		},
	}
	
	coll, err := ebpf.NewCollectionWithOptions(spec, opts)
	if err != nil {
		return fmt.Errorf("failed to create collection: %w", err)
	}
	defer coll.Close()

	// Open output CSV file
	outputFile, err := os.Create("/output/tc_trace.csv")
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer outputFile.Close()

	csvWriter := csv.NewWriter(outputFile)
	defer csvWriter.Flush()

	// Write header
	csvWriter.Write([]string{
		"timestamp_ns", "src_ip", "src_port", "dst_ip", "dst_port",
		"direction", "pattern_type", "pattern_offset", "data_len",
	})

	// Get packet count map
	packetCountMap := coll.Maps["packet_count"]
	if packetCountMap == nil {
		return fmt.Errorf("packet_count map not found")
	}

	// Open ringbuf reader
	rd, err := ringbuf.NewReader(coll.Maps["events"])
	if err != nil {
		return fmt.Errorf("failed to create ringbuf reader: %w", err)
	}
	defer rd.Close()

	// Handle signals
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	log.Println("Listening for TC events... Press Ctrl+C to stop")

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
			direction := "egress"
			if event.IsIngress > 0 {
				direction = "ingress"
			}

			// Get pattern name
			patternName := patternNames[event.PatternType]
			if event.PatternType == PATTERN_SILENCE {
				silencePatterns++
			}

			// Write to CSV
			csvWriter.Write([]string{
				fmt.Sprintf("%d", event.TimestampNs),
				srcIP, fmt.Sprintf("%d", event.SrcPort),
				dstIP, fmt.Sprintf("%d", event.DstPort),
				direction,
				patternName, fmt.Sprintf("%d", event.PatternOffset),
				fmt.Sprintf("%d", event.DataLen),
			})
			csvWriter.Flush()

			// Log interesting events
			if event.PatternType > 0 {
				log.Printf("PATTERN: %s:%d -> %s:%d %s pattern=%s offset=%d len=%d",
					srcIP, event.SrcPort, dstIP, event.DstPort,
					direction, patternName, event.PatternOffset, event.DataLen)
			} else if totalEvents <= 10 {
				// Debug first few events
				log.Printf("DEBUG: %s:%d -> %s:%d %s len=%d",
					srcIP, event.SrcPort, dstIP, event.DstPort,
					direction, event.DataLen)
			}
		}
	}()

	// Packet count checker
	go func() {
		for {
			time.Sleep(5 * time.Second)
			
			var key uint32 = 0
			var values []uint64
			if err := packetCountMap.Lookup(&key, &values); err == nil && len(values) > 0 {
				total := uint64(0)
				for _, v := range values {
					total += v
				}
				if total > 0 {
					log.Printf("Packets processed: %d", total)
				}
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
				log.Printf("TC events: %d, Silence patterns detected: %d",
					totalEvents, silencePatterns)
			} else {
				// Check packet count
				var key uint32 = 0
				var values []uint64
				if err := packetCountMap.Lookup(&key, &values); err == nil && len(values) > 0 {
					total := uint64(0)
					for _, v := range values {
						total += v
					}
					log.Printf("No audio events yet, but processed %d packets", total)
				}
			}
		}
	}
}

func intToIP(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", ip>>24, (ip>>16)&0xff, (ip>>8)&0xff, ip&0xff)
}