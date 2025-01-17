package parser

// NGCPStruct struct to hold the NGCP protocol data
type NGCPStruct struct {
	SDP         string
	Cookie      string
	CallID      string
	Anumber     string
	Bnumber     string
	FromTAG     string
	ToTAG       string
	SIPIP       string
	RE          string
	Comm        string
	ReceiveFrom string
	Count       int32
}
