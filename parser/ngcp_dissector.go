// Copyright 2025 Michele Campus michelecampus5@gmail.com
// Copyright 2025 QXIP B.V https://qxip.net
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

type NGCPMsgType int

const (
	REQUEST  NGCPMsgType = iota // 0
	RESPONSE                    // 1
)

type NGCPCommand int

const (
	OFFER  NGCPCommand = iota // 0
	ANSWER                    // 1
	DELETE                    // 2
	OK                        // 3
)

var debugLog bool

// parseField finds key in payload and parses its bencode-style value (len:data).
// offset is the number of bytes to skip after the key before looking for the colon.
// For most keys offset == len(key). For "received-from" offset is 19 (intentional protocol skip).
func parseField(payload, key string, offset int) (string, error) {
	idx := strings.Index(payload, key)
	if idx == -1 {
		return "", fmt.Errorf("%s not found", key)
	}
	sub := payload[idx+offset:]
	colonIdx := strings.Index(sub, ":")
	if colonIdx == -1 {
		return "", fmt.Errorf("malformed %s: missing colon", key)
	}
	length, err := strconv.Atoi(sub[:colonIdx])
	if err != nil {
		return "", fmt.Errorf("invalid %s length: %w", key, err)
	}
	end := colonIdx + 1 + length
	if end > len(sub) {
		return "", fmt.Errorf("%s length exceeds payload bounds", key)
	}
	return sub[colonIdx+1 : end], nil
}

// ParseNGCP parses the NGCP protocol
func ParseNGCP(packet gopacket.Packet, msg *Msg) (*NGCPStruct, error) {

	var ngcpData = &NGCPStruct{}
	var payload []byte

	// Print all layers detected in the packet
	if debugLog {
		log.Println("Layers found in the packet:")
		for _, layer := range packet.Layers() {
			log.Println(" - ", layer.LayerType())
		}
	}

	// TODO Check for linux cooked capture layer (SLL v2)

	// Check for Linux cooked capture layer (SLL v1)
	sllLayer := packet.Layer(layers.LayerTypeLinuxSLL)
	if sllLayer != nil && debugLog {
		log.Println("Linux Cooked Layer (SLL v1) found")
	}
	// Check for an Ethernet layer
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethLayer != nil && debugLog {
		log.Println("Ethernet layer found")
	}
	// Check for an IP layer
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		if debugLog {
			ip, _ := ipLayer.(*layers.IPv4)
			log.Println("IP layer found with SrcIP:", ip.SrcIP, "and DstIP:", ip.DstIP)
		}
	}
	// Check for IPv6 layer
	ip6Layer := packet.Layer(layers.LayerTypeIPv6)
	if ip6Layer != nil {
		if debugLog {
			ip6, _ := ip6Layer.(*layers.IPv6)
			log.Println("IP layer found with SrcIP:", ip6.SrcIP, "and DstIP:", ip6.DstIP)
		}
	}
	// Check for a TCP layer
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		if debugLog {
			tcp, _ := tcpLayer.(*layers.TCP)
			log.Println("TCP layer found with SrcPort:", tcp.SrcPort, "and DstPort:", tcp.DstPort)
		}
	}
	// Check for a UDP layer
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer != nil {
		if debugLog {
			udp, _ := udpLayer.(*layers.UDP)
			log.Println("UDP layer found with SrcPort:", udp.SrcPort, "and DstPort:", udp.DstPort)
		}
	}

	// Raw payload (last layer)
	appLayer := packet.ApplicationLayer()
	if appLayer != nil {
		payload = appLayer.Payload()
		if debugLog {
			log.Printf("Application layer payload size: %d\n", len(payload))
		}
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

	if strings.Contains(payload, "command") {
		return processRequestPayload(payload, ngcpData, msg)
	}

	if strings.Contains(payload, "result") {
		return processResponsePayload(payload, ngcpData, msg)
	}

	log.Println("Unsupported NGCP payload type")
	return errors.New("unsupported NGCP payload type")
}

// processRequestPayload handles REQUEST-type NGCP payloads
func processRequestPayload(payload string, ngcpData *NGCPStruct, msg *Msg) error {
	msg.NGCPType = REQUEST
	ngcpData.Type = "REQUEST"

	if strings.Contains(payload, "offer") {
		// Set command to OFFER
		msg.NGCPComm = OFFER
		ngcpData.Comm = "OFFER"

		/** FROM-TAG **/
		if err := parseFromTag(payload, ngcpData, msg); err != nil {
			return err
		}
		/** Anumber - Bnumber (Optional) **/
		if err := parseAnumberBnumber(payload, ngcpData, msg); err != nil {
			return err
		}
		/** SIP-IP (Optional) **/
		if err := parseSipIP(payload, ngcpData, msg); err != nil {
			return err
		}

	} else if strings.Contains(payload, "answer") {
		// Set command to ANSWER
		msg.NGCPComm = ANSWER
		ngcpData.Comm = "ANSWER"

		/** FROM-TAG **/
		if err := parseFromTag(payload, ngcpData, msg); err != nil {
			return err
		}
		/** TO-TAG **/
		if err := parseToTag(payload, ngcpData, msg); err != nil {
			return err
		}

	} else if strings.Contains(payload, "delete") {
		// Set command to DELETE
		msg.NGCPComm = DELETE
		ngcpData.Comm = "DELETE"
		log.Println("DELETE command found")
	} else {
		// Unsupported command type
		log.Println("Unsupported command type in NGCP payload")
		return errors.New("unsupported command type")
	}

	/** ReceiveFrom **/
	if err := parseReceivedFrom(payload, ngcpData, msg); err != nil {
		return err
	}
	/** Cookie**/
	if err := parseCookie(payload, ngcpData, msg); err != nil {
		return err
	}
	/** CallID **/
	if err := parseCallID(payload, ngcpData, msg); err != nil {
		return err
	}
	/** SDP **/
	if msg.NGCPComm == OFFER || msg.NGCPComm == ANSWER {
		if err := parseSDP(payload, ngcpData, msg); err != nil {
			return err
		}
	}

	return nil
}

// processResponsePayload handles RESPONSE-type NGCP payloads
func processResponsePayload(payload string, ngcpData *NGCPStruct, msg *Msg) error {
	// Set command to RESPONSE
	msg.NGCPType = RESPONSE
	ngcpData.Type = "RESPONSE"

	// Check for non-OK RESPONSE types
	if strings.Contains(payload, "pong") || strings.Contains(payload, "stats") || strings.Contains(payload, "warning") || strings.Contains(payload, "error") {
		log.Println("Non-OK RESPONSE type found, ignoring it")
		return nil
	}

	// Check for OK RESPONSE type
	if strings.Contains(payload, "ok") {
		msg.NGCPComm = OK
		ngcpData.Comm = "OK"
	} else {
		log.Println("Unsupported result type in NGCP payload")
		return errors.New("unsupported result type")
	}

	/** Cookie **/
	if err := parseCookie(payload, ngcpData, msg); err != nil {
		return err
	}
	/** SDP **/
	if err := parseSDP(payload, ngcpData, msg); err != nil {
		return err
	}

	return nil
}

/*** Helper functions:
* parseField
* parseFromTag
* parseToTag
* parseAnumberBnumber
* parseSipIP
* parseReceivedFrom
* parseCookie
* parseCallID
* parseSDP
***/
func parseFromTag(payload string, ngcpData *NGCPStruct, msg *Msg) error {
	val, err := parseField(payload, "from-tag", len("from-tag"))
	if err != nil {
		return fmt.Errorf("no FROM-TAG found: %w", err)
	}
	ngcpData.FromTAG = val
	msg.SIP.FromTag = val
	msg.SIP.HasFromTag = true
	return nil
}

func parseToTag(payload string, ngcpData *NGCPStruct, msg *Msg) error {
	val, err := parseField(payload, "to-tag", len("to-tag"))
	if err != nil {
		return fmt.Errorf("no TO-TAG found: %w", err)
	}
	ngcpData.ToTAG = val
	msg.SIP.ToTag = val
	msg.SIP.HasToTag = true
	return nil
}

func parseAnumberBnumber(payload string, ngcpData *NGCPStruct, msg *Msg) error {
	hasAnumber := strings.Contains(payload, "anumber")
	hasBnumber := strings.Contains(payload, "bnumber")

	// Validate presence of both numbers
	if hasAnumber && !hasBnumber {
		return errors.New("missing BNUMBER but ANUMBER is present")
	}
	if !hasAnumber && hasBnumber {
		return errors.New("missing ANUMBER but BNUMBER is present")
	}

	if hasAnumber {
		val, err := parseField(payload, "anumber", len("anumber"))
		if err != nil {
			return err
		}
		ngcpData.Anumber = val
		msg.SIP.FromUser = val
	}

	if hasBnumber {
		val, err := parseField(payload, "bnumber", len("bnumber"))
		if err != nil {
			return err
		}
		ngcpData.Bnumber = val
		msg.SIP.ToUser = val
	}

	return nil
}

func parseSipIP(payload string, ngcpData *NGCPStruct, msg *Msg) error {
	if strings.Contains(payload, "sipip") {
		val, err := parseField(payload, "sipip", len("sipip"))
		if err != nil {
			return err
		}
		ngcpData.SipIP = val
		msg.SIP.NgcpSipip = val
	}
	return nil
}

func parseReceivedFrom(payload string, ngcpData *NGCPStruct, msg *Msg) error {
	if !strings.Contains(payload, "received-from") {
		log.Println("no RECEIVED-FROM found, ignoring it")
		return nil
	}

	val, err := parseField(payload, "received-from", 19)
	if err != nil {
		return fmt.Errorf("malformed RECEIVED-FROM: %w", err)
	}
	ngcpData.ReceiveFrom = val
	msg.SIP.RuriUser = val
	return nil
}

func parseCookie(payload string, ngcpData *NGCPStruct, msg *Msg) error {
	endCookie := strings.Index(payload, " ")
	if endCookie == -1 {
		return errors.New("no space found in payload for cookie extraction")
	}
	ngcpData.Cookie = payload[:endCookie]
	msg.SIP.NgcpCookie = ngcpData.Cookie

	return nil
}

func parseCallID(payload string, ngcpData *NGCPStruct, msg *Msg) error {
	val, err := parseField(payload, "call-id", len("call-id"))
	if err != nil {
		return fmt.Errorf("no CALL-ID found: %w", err)
	}
	ngcpData.CallID = val
	msg.SIP.CallID = val

	return nil
}

func parseSDP(payload string, ngcpData *NGCPStruct, msg *Msg) error {
	val, err := parseField(payload, "sdp", len("sdp"))
	if err != nil {
		return fmt.Errorf("no SDP found: %w", err)
	}
	ngcpData.Sdp = val
	msg.SIP.Body = val

	return nil
}
