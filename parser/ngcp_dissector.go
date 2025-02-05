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

const (
	REQUEST  = iota // 0
	RESPONSE        // 1
)
const (
	OFFER  = iota // 0
	ANSWER        // 1
	DELETE        // 2
	OK            // 3
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

	/** CallID **/
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
* parseFromTag
* parseToTag
* parseAnumberBnumber
* parseSipIP
* parseReceivedFrom
* parseCookieAndCallID
* parseSDP
***/
func parseFromTag(payload string, ngcpData *NGCPStruct, msg *Msg) error {
	if !strings.Contains(payload, "from-tag") {
		log.Println("no FROM-TAG found")
		return errors.New("no FROM-TAG found")
	}

	fromTag := strNstr(payload, "from-tag", len(payload))
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
	ngcpData.FromTAG = fromTag[colonIdx+1 : colonIdx+1+fromTagLen]
	msg.SIP.FromTag = fromTag[colonIdx+1 : colonIdx+1+fromTagLen]
	msg.SIP.HasFromTag = true
	return nil
}

func parseToTag(payload string, ngcpData *NGCPStruct, msg *Msg) error {
	if !strings.Contains(payload, "to-tag") {
		log.Println("no TO-TAG found")
		return errors.New("no TO-TAG found")
	}

	toTag := strNstr(payload, "to-tag", len(payload))
	toTag = toTag[6:]
	colonIdx := strings.Index(toTag, ":")
	if colonIdx == -1 {
		log.Println("error in check NGCP: malformed TO-TAG")
		return errors.New("malformed TO-TAG")
	}
	toTagLen, err := strconv.Atoi(toTag[:colonIdx])
	if err != nil {
		return errors.New("invalid TO-TAG length")
	}
	ngcpData.ToTAG = toTag[colonIdx+1 : colonIdx+1+toTagLen]
	msg.SIP.ToTag = toTag[colonIdx+1 : colonIdx+1+toTagLen]
	msg.SIP.HasToTag = true
	return nil
}

func parseAnumberBnumber(payload string, ngcpData *NGCPStruct, msg *Msg) error {
	var skipANumber, skipBNumber bool

	// Check if ANumber is missing
	if !strings.Contains(payload, "anumber") {
		skipANumber = true
		// Check if BNumber is missing
		if !strings.Contains(payload, "bnumber") {
			skipBNumber = true
		}
	}

	// Validate presence of both numbers
	if skipANumber && !skipBNumber {
		return errors.New("missing ANUMBER but BNUMBER is present")
	} else if !skipANumber && skipBNumber {
		return errors.New("missing BNUMBER but ANUMBER is present")
	}

	// Parse ANumber (both ANumber and BNumber are present)
	if !skipANumber {
		aNumber := strNstr(payload, "anumber", len(payload))
		aNumber = aNumber[7:]
		colonIdx := strings.Index(aNumber, ":")
		if colonIdx == -1 {
			return errors.New("malformed ANUMBER")
		}
		aNumberLen, err := strconv.Atoi(aNumber[:colonIdx])
		if err != nil {
			return errors.New("invalid ANUMBER length")
		}
		ngcpData.Anumber = aNumber[colonIdx+1 : colonIdx+1+aNumberLen]
		msg.SIP.FromUser = ngcpData.Anumber
	}

	// Parse BNumber
	if !skipBNumber {
		bNumber := strNstr(payload, "bnumber", len(payload))
		bNumber = bNumber[7:]
		colonIdx := strings.Index(bNumber, ":")
		if colonIdx == -1 {
			return errors.New("malformed BNUMBER")
		}
		bNumberLen, err := strconv.Atoi(bNumber[:colonIdx])
		if err != nil {
			return errors.New("invalid BNUMBER length")
		}
		ngcpData.Bnumber = bNumber[colonIdx+1 : colonIdx+1+bNumberLen]
		msg.SIP.FromUser = ngcpData.Bnumber
	}

	return nil
}

func parseSipIP(payload string, ngcpData *NGCPStruct, msg *Msg) error {
	var skipSipIP bool

	if !strings.Contains(payload, "sipip") {
		skipSipIP = true
	}

	if !skipSipIP {
		sipIP := strNstr(payload, "sipip", len(payload))
		sipIP = sipIP[5:]
		colonIdx := strings.Index(sipIP, ":")
		if colonIdx == -1 {
			log.Println("error in check NGCP: malformed SIP-IP")
			return errors.New("malformed SIP-IP")
		}
		sipIPLen, err := strconv.Atoi(sipIP[:colonIdx])
		if err != nil {
			log.Println("invalid SIP-IP length")
			return errors.New("invalid SIP-IP length")
		}
		ngcpData.SipIP = sipIP[colonIdx+1 : colonIdx+1+sipIPLen]
		msg.SIP.NgcpSipip = sipIP[colonIdx+1 : colonIdx+1+sipIPLen]
	}
	return nil
}

func parseReceivedFrom(payload string, ngcpData *NGCPStruct, msg *Msg) error {
	if !strings.Contains(payload, "received-from") {
		log.Println("no RECEIVED-FROM found, ignoring it")
		return nil
	}

	receivedFrom := strNstr(payload, "received-from", len(payload))
	receivedFrom = receivedFrom[19:]
	colonIdx := strings.Index(receivedFrom, ":")
	if colonIdx == -1 {
		log.Println("error in check NGCP: malformed RECEIVED-FROM")
		return errors.New("malformed RECEIVED-FROM")
	}
	receivedFromLen, err := strconv.Atoi(receivedFrom[:colonIdx])
	if err != nil {
		return errors.New("invalid RECEIVED-FROM length")
	}
	ngcpData.ReceiveFrom = receivedFrom[colonIdx+1 : colonIdx+1+receivedFromLen]
	msg.SIP.RuriUser = receivedFrom[colonIdx+1 : colonIdx+1+receivedFromLen]
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
	if !strings.Contains(payload, "call-id") {
		return errors.New("no CALL-ID found")
	}

	callID := strNstr(payload, "call-id", len(payload))
	callID = callID[7:]
	colonIdx := strings.Index(callID, ":")
	if colonIdx == -1 {
		log.Println("error in check NGCP: malformed CALL-ID")
		return errors.New("malformed CALL-ID")
	}
	callIDLen, err := strconv.Atoi(callID[:colonIdx])
	if err != nil {
		return errors.New("invalid CALL-ID length")
	}
	ngcpData.CallID = callID[colonIdx+1 : colonIdx+1+callIDLen]
	msg.SIP.CallID = callID[colonIdx+1 : colonIdx+1+callIDLen]

	return nil
}

func parseSDP(payload string, ngcpData *NGCPStruct, msg *Msg) error {
	if !strings.Contains(payload, "sdp") {
		return errors.New("no SDP found")
	}

	sdp := strNstr(payload, "sdp", len(payload))
	sdp = sdp[3:]
	colonIdx := strings.Index(sdp, ":")
	if colonIdx == -1 {
		log.Println("error in check NGCP: malformed SDP")
		return errors.New("malformed SDP")
	}
	sdpLen, err := strconv.Atoi(sdp[:colonIdx])
	if err != nil {
		log.Println("invalid SDP length")
		return errors.New("invalid SDP length")
	}
	ngcpData.Sdp = sdp[colonIdx+1 : colonIdx+1+sdpLen]
	msg.SIP.Body = sdp[colonIdx+1 : colonIdx+1+sdpLen]

	return nil
}
