package parser

// NGCPStruct struct to hold the NGCP protocol data
type NGCPStruct struct {
	Type        string // REQUEST, RESPONSE
	Comm        string // OFFER, ANSWER, DELETE, PING
	Sdp         string
	Cookie      string
	CallID      string
	Anumber     string
	Bnumber     string
	FromTAG     string
	ToTAG       string
	SipIP       string
	ReceiveFrom string
	Count       int32
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
}

// Msg struct to hold the parsed message
type Msg struct {
	NGCPType int // REQUEST, RESPONSE
	NGCPComm int // OFFER, ANSWER, DELETE, PING
	SIP      SIP
}
