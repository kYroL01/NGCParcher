package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func main() {
	interfaceName := flag.String("interface", "", "Name of the interface to capture packets from")
	pcapFile := flag.String("pcap", "", "Path to the pcap file to read")
	flag.Parse()

	if *interfaceName == "" && *pcapFile == "" {
		log.Fatal("You must specify either a network interface or a pcap file")
	}

	if *interfaceName != "" {
		readLiveTraffic(*interfaceName)
	} else {
		readPcapFile(*pcapFile)
	}
}

// readLiveTraffic captures live traffic from the specified network interface
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

// readPcapFile reads packets from a pcap file
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
