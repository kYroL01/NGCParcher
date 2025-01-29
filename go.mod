module ngcp_archer

go 1.22.1

toolchain go1.22.11

require (
	github.com/google/gopacket v1.1.19
	github.com/qxip/rtpagent-go v0.0.0-00010101000000-000000000000
)

require (
	github.com/spf13/pflag v1.0.5
	golang.org/x/sys v0.28.0 // indirect
)

replace github.com/qxip/rtpagent-go => ./external/smartpagent-go
