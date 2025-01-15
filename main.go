// Copyright 2025 Michele Campus michelecampus5@gmail.com
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

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

// listAvailableDevices lists all the available network devices
func listAvailableDevices() {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatalf("Error finding devices: %v", err)
	}

	fmt.Println("Available devices:")
	for _, device := range devices {
		fmt.Printf("Name: %s, Description: %s\n", device.Name, device.Description)
	}
}

// parseOptions parses the command-line options
func parseOptions() Options {
	// Define flags
	interfaceName := flag.String("interface", "", "Name of the interface to capture packets from")
	pcapFile := flag.String("pcap", "", "Path to the pcap file to read")
	listDevices := flag.Bool("list", false, "List available devices")

	// Parse flags
	flag.Parse()

	// Check if the listDevices flag is provided
	if *listDevices {
		listAvailableDevices()
		os.Exit(0)
	}

	// Check if at least one option is provided for interface or pcap file
	if *interfaceName == "" && *pcapFile == "" {
		fmt.Println("Usage:")
		flag.PrintDefaults()
		os.Exit(0)
	}

	return Options{
		Interface: *interfaceName,
		PcapFile:  *pcapFile,
	}
}

func main() {

	fmt.Printf(">>--- WELCOME to ngcp_archer %s--->\n", version)
	// Parse options
	opts := parseOptions()

	if opts.Interface != "" {
		readLiveTraffic(opts.Interface)
	} else {
		readPcapFile(opts.PcapFile)
	}
}

// readLiveTraffic reads live traffic from the specified interface
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
