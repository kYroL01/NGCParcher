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

package parser

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// ParseNGCP parses the NGCP protocol
func ParseNGCP(packet gopacket.Packet) (*NGCPStruct, error) {

	ngcpData := &NGCPStruct{}
	var payload []byte

	// Print all layers detected in the packet
	fmt.Println("Layers found in the packet:")
	for _, layer := range packet.Layers() {
		fmt.Println(" - ", layer.LayerType())
	}

	// TODO Check for linux cooked capture layer (SLL v2)

	// Check for Linux cooked capture layer (SLL v1)
	sllLayer := packet.Layer(layers.LayerTypeLinuxSLL)
	if sllLayer != nil {
		fmt.Println("Linux Cooked Layer (SLL v1) found")
	}
	// Check for an Ethernet layer
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethLayer != nil {
		fmt.Println("Ethernet layer found")
	}
	// Check for an IP layer
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		fmt.Println("IP layer found with SrcIP:", ip.SrcIP, "and DstIP:", ip.DstIP)
	}
	// Check for IPv6 layer
	ip6Layer := packet.Layer(layers.LayerTypeIPv6)
	if ip6Layer != nil {
		ip6, _ := ip6Layer.(*layers.IPv6)
		fmt.Println("IP layer found with SrcIP:", ip6.SrcIP, "and DstIP:", ip6.DstIP)
	}
	// Check for a TCP layer
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		fmt.Println("TCP layer found with SrcPort:", tcp.SrcPort, "and DstPort:", tcp.DstPort)
	}
	// Check for a UDP layer
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		fmt.Println("UDP layer found with SrcPort:", udp.SrcPort, "and DstPort:", udp.DstPort)
	}

	// Raw payload (last layer)
	appLayer := packet.ApplicationLayer()
	if appLayer != nil {
		payload = appLayer.Payload()
		fmt.Printf("Application layer payload size: %d\n", len(payload))
	}

	return ngcpData, nil
}
