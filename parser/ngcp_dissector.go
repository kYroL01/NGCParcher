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
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const (
	REQUEST  = iota // 0
	RESPONSE        // 1
)
const (
	OFFER  = iota // 0
	ANSWER        // 1
	DELETE        // 2
	PING          // 3
)

func strNstr(haystack, needle string, maxLen int) string {
	// Ensure we limit haystack to maxLen characters
	if len(haystack) > maxLen {
		haystack = haystack[:maxLen]
	}

	index := strings.Index(haystack, needle)
	if index == -1 {
		return ""
	}

	return haystack[index:]
}

// ParseNGCP parses the NGCP protocol
func ParseNGCP(packet gopacket.Packet, msg *Msg) (*NGCPStruct, error) {

	var ngcpData = &NGCPStruct{}
	var payload []byte

	// Print all layers detected in the packet
	log.Println("Layers found in the packet:")
	for _, layer := range packet.Layers() {
		log.Println(" - ", layer.LayerType())
	}

	// TODO Check for linux cooked capture layer (SLL v2)

	// Check for Linux cooked capture layer (SLL v1)
	sllLayer := packet.Layer(layers.LayerTypeLinuxSLL)
	if sllLayer != nil {
		log.Println("Linux Cooked Layer (SLL v1) found")
	}
	// Check for an Ethernet layer
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethLayer != nil {
		log.Println("Ethernet layer found")
	}
	// Check for an IP layer
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		log.Println("IP layer found with SrcIP:", ip.SrcIP, "and DstIP:", ip.DstIP)
	}
	// Check for IPv6 layer
	ip6Layer := packet.Layer(layers.LayerTypeIPv6)
	if ip6Layer != nil {
		ip6, _ := ip6Layer.(*layers.IPv6)
		log.Println("IP layer found with SrcIP:", ip6.SrcIP, "and DstIP:", ip6.DstIP)
	}
	// Check for a TCP layer
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		log.Println("TCP layer found with SrcPort:", tcp.SrcPort, "and DstPort:", tcp.DstPort)
	}
	// Check for a UDP layer
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		log.Println("UDP layer found with SrcPort:", udp.SrcPort, "and DstPort:", udp.DstPort)
	}

	// Raw payload (last layer)
	appLayer := packet.ApplicationLayer()
	if appLayer != nil {
		payload = appLayer.Payload()
		log.Printf("Application layer payload size: %d\n", len(payload))
		if len(payload) == 0 {
			return nil, errors.New("application layer payload is empty")
		}

		err := processNGCPPayload(string(payload), ngcpData, msg)
		if err != nil {
			return nil, fmt.Errorf("error processing NGCP payload: %w", err)
		}
	} else {
		return nil, errors.New("no application layer found in packet")
	}

	return ngcpData, nil
}

// processNGCPPayload processes the NGCP protocol payload and populates the NGCPStruct
func processNGCPPayload(payload string, ngcpData *NGCPStruct, msg *Msg) error {

	// Check if the payload is empty
	if payload == "" {
		log.Println("error: empty payload in NGCP parser")
		return errors.New("empty payload")
	}

	var (
		//sdp         string = ""
		//cookie      string = ""
		//callID      string = ""
		aNumber string = ""
		bNumber string = ""
		fromTag string = ""
		//toTag       string = ""
		sipIP string = ""
		//receiveFrom string = ""
		skipANumber bool = false
		skipBNumber bool = false
		skipSipIP   bool = false
	)

	/**
	 ** This is a REQUEST (0)
	 **/
	if strings.Contains(payload, "command") {

		// Update flag for request
		msg.NGCPType = REQUEST
		ngcpData.Type = "REQUEST"

		// Check command type
		if strings.Contains(payload, "offer") {
			// Update flag for offer
			msg.NGCPComm = OFFER
			ngcpData.Comm = "OFFER"

			/** FROM TAG **/
			fromTag = strNstr(payload, "from-tag", len(payload))
			if fromTag == "" {
				log.Println("error in check NGCP: no FROM-TAG found")
				return errors.New("no FROM-TAG found")
			}
			fromTag = fromTag[8:]
			colonIdx := strings.Index(fromTag, ":")
			if colonIdx == -1 {
				log.Println("error in check NGCP: malformed FROM-TAG")
				return errors.New("malformed FROM-TAG")
			}
			fromTagLen, err := strconv.Atoi(fromTag[:colonIdx])
			if err != nil {
				return errors.New("invalid FROM-TAG length")
			}
			// Update NGCPStruct
			ngcpData.FromTAG = fromTag[colonIdx+1 : colonIdx+1+fromTagLen]
			// Update SIP struct in Msg
			msg.SIP.FromTag = fromTag[colonIdx+1 : colonIdx+1+fromTagLen]
			msg.SIP.HasFromTag = true

			/*
			* Check if Anumber and Bnumber are present
			* if Anumber is present then Bnumber is also present, and viceversa
			* if one of the two is present but not the other, then it's an error
			 */
			if !strings.Contains(payload, "anumber") {
				skipANumber = true
				if !strings.Contains(payload, "bnumber") {
					skipBNumber = true
				}
			}
			if skipANumber && !skipBNumber {
				log.Println("error in check NGCP: missing ANUMBER but BNUMBER is present")
				return errors.New("missing ANUMBER but BNUMBER is present")
			} else if !skipANumber && skipBNumber {
				log.Println("error in check NGCP: missing BNUMBER but ANUMBER is present")
				return errors.New("missing BNUMBER but ANUMBER is present")
			}

			/** ANumber **/
			if !skipANumber {
				aNumber = strNstr(payload, "anumber", len(payload))
				aNumber = aNumber[7:]
				colonIdx = strings.Index(aNumber, ":")
				if colonIdx == -1 {
					log.Println("error in check NGCP: malformed ANUMBER")
					return errors.New("malformed ANUMBER")
				}
				aNumberLen, err := strconv.Atoi(aNumber[:colonIdx])
				if err != nil {
					return errors.New("invalid ANUMBER length")
				}
				// Update NGCPStruct
				ngcpData.Anumber = aNumber[colonIdx+1 : colonIdx+1+aNumberLen]
				// Update SIP struct in Msg
				msg.SIP.FromUser = aNumber[colonIdx+1 : colonIdx+1+aNumberLen]
			}
			/** BNumber **/
			if !skipBNumber {
				bNumber = strNstr(payload, "bnumber", len(payload))
				bNumber = bNumber[7:]
				colonIdx = strings.Index(bNumber, ":")
				if colonIdx == -1 {
					log.Println("error in check NGCP: malformed ANUMBER")
					return errors.New("malformed BNUMBER")
				}
				bNumberLen, err := strconv.Atoi(bNumber[:colonIdx])
				if err != nil {
					return errors.New("invalid BNUMBER length")
				}
				// Update NGCPStruct
				ngcpData.Bnumber = bNumber[colonIdx+1 : colonIdx+1+bNumberLen]
				// Update SIP struct in Msg
				msg.SIP.FromUser = bNumber[colonIdx+1 : colonIdx+1+bNumberLen]
			}

			/* Check if SIP-IP is present */
			if !strings.Contains(payload, "sipip") {
				skipSipIP = true
			}
			/* SIP-IP*/
			if !skipSipIP {
				sipIP = strNstr(payload, "sipip", len(payload))
				sipIP = sipIP[5:]
				colonIdx = strings.Index(sipIP, ":")
				if colonIdx == -1 {
					log.Println("error in check NGCP: malformed SIP-IP")
					return errors.New("malformed SIP-IP")
				}
				sipIPLen, err := strconv.Atoi(sipIP[:colonIdx])
				if err != nil {
					return errors.New("invalid SIP-IP length")
				}
				// Update NGCPStruct
				ngcpData.SipIP = sipIP[colonIdx+1 : colonIdx+1+sipIPLen]
				// Update SIP struct in Msg
				msg.SIP.NgcpSipip = sipIP[colonIdx+1 : colonIdx+1+sipIPLen]
			}

		} else if strings.Contains(payload, "answer") {
			msg.NGCPComm = ANSWER
			ngcpData.Comm = "ANSWER"

		} else if strings.Contains(payload, "delete") {
			msg.NGCPComm = DELETE
		} else if strings.Contains(payload, "ping") {
			msg.NGCPComm = PING
		} else {
			log.Println("Unsupported command type in NGCP payload")
			return errors.New("unsupported command type")
		}

		return nil
	}
	return nil
}
