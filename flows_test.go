package gomat

import (
	"net"
	"strings"
	"testing"
)

// TestCommissionRejectsEqualIDs verifies that Commission returns an error
// when controller_id == device_id. This prevents SignCertificate for the
// device from overwriting the controller's certificate file, which would
// cause CASE to fail with a key mismatch.
func TestCommissionRejectsEqualIDs(t *testing.T) {
	err := Commission(nil, net.ParseIP("127.0.0.1"), 20202021, 1, 1)
	if err == nil {
		t.Fatal("expected error when controller_id == device_id, got nil")
	}
	if !strings.Contains(err.Error(), "must be different") {
		t.Fatalf("unexpected error message: %s", err.Error())
	}
}
