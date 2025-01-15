package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

const version = "1.0.0"

// Options struct to hold the command-line options
type Options struct {
	Interface string
	PcapFile  string
}

func parseOptions() Options {
	// Define flags
	interfaceName := flag.String("interface", "", "Name of the interface to capture packets from")
	pcapFile := flag.String("pcap", "", "Path to the pcap file to read")

	// Parse the flags
	flag.Parse()

	// Check if at least one option is provided
	if *interfaceName == "" && *pcapFile == "" {
		fmt.Println("Usage:")
		flag.PrintDefaults()
		os.Exit(1)
	}

	return Options{
		Interface: *interfaceName,
		PcapFile:  *pcapFile,
	}
}

func main() {
	// Parse options
	opts := parseOptions()

	if opts.Interface != "" {
		readLiveTraffic(opts.Interface)
	} else {
		readPcapFile(opts.PcapFile)
	}
}

func readLiveTraffic(interfaceName string) {
	handle, err := pcap.OpenLive(interfaceName, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("Error opening live capture: %v", err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		fmt.Println(packet)
	}
}

func readPcapFile(filename string) {
	handle, err := pcap.OpenOffline(filename)
	if err != nil {
		log.Fatalf("Error opening pcap file: %v", err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		fmt.Println(packet)
	}
}
