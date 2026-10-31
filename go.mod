module github.com/kuzzrus/keenetic-xray-go

go 1.26.0

// Go >= 1.24 opens MPTCP listeners by default on Linux. The root exploit for
// the Linux kernel IPv4 TCP use-after-free (CVE-2026-98432, golang/go#82717)
// targets them, and nothing here needs MPTCP -- see
// cmd/keenetic-xray-control-server/mptcp_test.go.
godebug multipathtcp=0

require golang.org/x/crypto v0.58.0

require (
	golang.org/x/net v0.61.0 // indirect
	golang.org/x/text v0.43.0 // indirect
)
