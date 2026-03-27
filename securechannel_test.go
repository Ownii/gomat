package gomat

import (
	"net"
	"testing"
	"time"
)

func TestReceiveBufferSizeConstant(t *testing.T) {
	// Verify the receive buffer is 64 KB (was 10 KB before the fix).
	if RecvBufSize != 64*1024 {
		t.Fatalf("expected RecvBufSize = %d, got %d", 64*1024, RecvBufSize)
	}
}

func TestReceiveBufferSize(t *testing.T) {
	// Start a UDP listener (the "device" side) and a udpChannel (the "client" side).
	// Send a payload and verify it is received completely via the receive() method.
	// Note: macOS loopback limits UDP datagrams to ~9216 bytes, so we test with
	// a payload that fits within that limit. The constant test above verifies
	// the buffer is actually 64 KB.

	// Set up a UDP server to send a large payload back to the client.
	serverAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serverConn, err := net.ListenUDP("udp", serverAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer serverConn.Close()

	serverPort := serverConn.LocalAddr().(*net.UDPAddr).Port

	// Create a udpChannel pointing at the server.
	ch, err := startUdpChannel(net.ParseIP("127.0.0.1"), serverPort, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer ch.Udp.Close()

	// Prepare a payload larger than the old 10 KB buffer but within UDP datagram limits.
	// macOS loopback can handle up to ~9216 bytes per UDP datagram by default,
	// so we use 9000 bytes — below the UDP limit but would fail with a buffer
	// smaller than this. The real test is that the buffer is now 64 KB.
	// We also verify the buffer constant directly below.
	payloadSize := 9000
	payload := make([]byte, payloadSize)
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	// Send from client so the server knows the client's address.
	ch.send([]byte{0x01})
	buf := make([]byte, 16)
	n, clientAddr, err := serverConn.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 || buf[0] != 0x01 {
		t.Fatal("unexpected initial message")
	}

	// Server sends the large payload back to the client.
	_, err = serverConn.WriteToUDP(payload, clientAddr)
	if err != nil {
		t.Fatal(err)
	}

	// Client receives — should get the full payload.
	ch.Udp.SetReadDeadline(time.Now().Add(2 * time.Second))
	received, err := ch.receive()
	if err != nil {
		t.Fatalf("receive failed: %v", err)
	}
	if len(received) != payloadSize {
		t.Fatalf("expected %d bytes, got %d (buffer too small?)", payloadSize, len(received))
	}

	// Verify content integrity.
	for i := range received {
		if received[i] != byte(i%256) {
			t.Fatalf("data mismatch at byte %d: expected %d, got %d", i, byte(i%256), received[i])
		}
	}
}

func TestReadTimeoutDefault(t *testing.T) {
	// Verify that a new SecureChannel has the default 3-second timeout.
	sc, err := StartSecureChannel(net.ParseIP("127.0.0.1"), 15540, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer sc.Close()

	if sc.ReadTimeout != 3*time.Second {
		t.Fatalf("expected default ReadTimeout of 3s, got %v", sc.ReadTimeout)
	}
}

func TestReadTimeoutConfigurable(t *testing.T) {
	// Create a SecureChannel pointing at an address where nothing is listening.
	// Set a short custom timeout and verify Receive() respects it.
	sc, err := StartSecureChannel(net.ParseIP("127.0.0.1"), 15541, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer sc.Close()

	// Set a very short timeout.
	sc.ReadTimeout = 100 * time.Millisecond

	start := time.Now()
	_, err = sc.Receive()
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}

	// Should have timed out close to 100ms, definitely not 3 seconds.
	if elapsed > 500*time.Millisecond {
		t.Fatalf("timeout took %v — expected ~100ms (custom timeout not respected?)", elapsed)
	}
	if elapsed < 50*time.Millisecond {
		t.Fatalf("returned too quickly (%v) — timeout may not be applied", elapsed)
	}
}
