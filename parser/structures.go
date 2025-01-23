package parser

// NGCPStruct struct to hold the NGCP protocol data
type NGCPStruct struct {
	Type        string // REQUEST, RESPONSE
	Comm        string // OFFER, ANSWER, DELETE, OK
	Sdp         string
	Cookie      string
	CallID      string
	Anumber     string
	Bnumber     string
	FromTAG     string
	ToTAG       string
	SipIP       string
	ReceiveFrom string
}

// sdpMediaDesc struct for SDP parsing
type sdpMediaDesc struct {
	MediaType []byte // Named portion of URI
	Port      []byte // Port number
	Proto     []byte // Protocol
	Fmt       []byte // Fmt
	Src       []byte // Full source if needed
}

// sdpAttrib struct for SDP parsing
type sdpAttrib struct {
	Cat []byte // Named portion of URI
	Val []byte // Port number
	Src []byte // Full source if needed
}

// sdpConnData struct for SDP parsing
type sdpConnData struct {
	AddrType []byte // Address Type
	ConnAddr []byte // Connection Address
	Src      []byte // Full source if needed
}

// SdpMsg struct to hold the SDP protocol data
type SdpMsg struct {
	MediaDesc sdpMediaDesc
	Attrib    []sdpAttrib
	ConnData  sdpConnData
}

// SIP struct to hold SIP protocol data
type SIP struct {
	Method     string
	StatusCode int
	Headers    map[string]string
	Body       string
	FromTag    string
	HasFromTag bool
	FromUser   string
	ToTag      string
	HasToTag   bool
	RuriUser   string
	NgcpSipip  string
	NgcpCookie string
	CallID     string
	HasSdp     bool
	Sdp        SdpMsg
}

// Msg struct to hold the parsed message
type Msg struct {
	NGCPType int // REQUEST, RESPONSE
	NGCPComm int // OFFER, ANSWER, DELETE, OK
	SIP      SIP
}
