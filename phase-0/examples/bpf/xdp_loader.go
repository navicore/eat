// xdp_loader.go - Userspace loader for XDP-based eBPF audio tracer
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
	DataLen       uint32
	PktCount      uint32
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

	// Load eBPF program spec
	spec, err := ebpf.LoadCollectionSpec("xdp_audio_tracer.o")
	if err != nil {
		return fmt.Errorf("failed to load eBPF spec: %w", err)
	}

	// We only need to access the maps (program is already attached via ip link)
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("failed to create collection: %w", err)
	}
	defer coll.Close()

	// Open output CSV file
	outputFile, err := os.Create("/output/xdp_trace.csv")
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer outputFile.Close()

	csvWriter := csv.NewWriter(outputFile)
	defer csvWriter.Flush()

	// Write header
	csvWriter.Write([]string{
		"timestamp_ns", "src_ip", "src_port", "dst_ip", "dst_port",
		"pattern_type", "pattern_offset", "data_len", "pkt_count",
	})

	// Get packet count map
	pktCountMap := coll.Maps["pkt_count"]
	if pktCountMap == nil {
		return fmt.Errorf("pkt_count map not found")
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

	log.Println("Listening for XDP events... Press Ctrl+C to stop")

	// Stats
	var totalEvents, silencePatterns uint64
	var lastPktCount uint64
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	// Packet count monitor
	go func() {
		for {
			time.Sleep(5 * time.Second)
			
			var key uint32 = 0
			var values []uint64
			if err := pktCountMap.Lookup(&key, &values); err == nil && len(values) > 0 {
				total := uint64(0)
				for _, v := range values {
					total += v
				}
				if total > lastPktCount {
					log.Printf("Total packets processed: %d (delta: %d)", total, total-lastPktCount)
					lastPktCount = total
				}
			}
		}
	}()

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
				patternName, fmt.Sprintf("%d", event.PatternOffset),
				fmt.Sprintf("%d", event.DataLen),
				fmt.Sprintf("%d", event.PktCount),
			})
			csvWriter.Flush()

			// Log interesting events
			if event.PatternType > 0 {
				log.Printf("PATTERN DETECTED: %s:%d -> %s:%d pattern=%s offset=%d len=%d pkt#=%d",
					srcIP, event.SrcPort, dstIP, event.DstPort,
					patternName, event.PatternOffset, event.DataLen, event.PktCount)
			} else if totalEvents <= 10 {
				// Debug first few events
				log.Printf("Audio packet: %s:%d -> %s:%d len=%d pkt#=%d",
					srcIP, event.SrcPort, dstIP, event.DstPort,
					event.DataLen, event.PktCount)
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
				log.Printf("XDP events captured: %d, Silence patterns detected: %d",
					totalEvents, silencePatterns)
			}
		}
	}
}

func intToIP(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", ip>>24, (ip>>16)&0xff, (ip>>8)&0xff, ip&0xff)
}