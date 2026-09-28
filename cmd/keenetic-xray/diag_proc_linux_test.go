//go:build linux

package main

import (
	"os"
	"slices"
	"strings"
	"testing"
)

func TestDiagProc_ReadsThisProcess(t *testing.T) {
	total, avail, err := memInfo()
	if err != nil || total <= 0 || avail <= 0 || avail > total {
		t.Fatalf("memInfo = %d, %d, %v", total, avail, err)
	}
	u, err := procUsageOf(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if u.RSSKB <= 0 || u.FDs <= 0 || u.FDLimit == "" || u.Args == "" {
		t.Errorf("procUsageOf(self) = %+v", u)
	}
	comm, err := os.ReadFile("/proc/self/comm")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(pidsNamed(strings.TrimSpace(string(comm))), os.Getpid()) {
		t.Error("pidsNamed did not find this process by its own comm")
	}
}
