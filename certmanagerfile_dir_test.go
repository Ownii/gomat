package gomat

import (
	"os"
	"path/filepath"
	"testing"
)

// The directory-taking constructor ignores the environment — that is its
// point: this library no longer reads PEM_DIR, the directory comes from the
// calling application.
func TestNewFileCertManagerInDirIgnoresEnv(t *testing.T) {
	t.Setenv("PEM_DIR", "/definitely/ignored")

	if got := NewFileCertManagerInDir(1, "/tmp/x").dir; got != "/tmp/x" {
		t.Errorf("explicit dir: got %q, want %q", got, "/tmp/x")
	}
	// An empty dir means "use the default", not "use the environment".
	if got := NewFileCertManagerInDir(1, "").dir; got != "pem" {
		t.Errorf("empty dir: got %q, want %q", got, "pem")
	}
}

// The old constructor keeps behaving exactly as it did before the change:
// default "pem", overridden by PEM_DIR. Other checkouts build against this
// same fork and must not silently switch their certificate directory.
func TestNewFileCertManagerKeepsEnvBehaviour(t *testing.T) {
	t.Setenv("PEM_DIR", "/tmp/from-env")
	if got := NewFileCertManager(1).dir; got != "/tmp/from-env" {
		t.Errorf("with PEM_DIR set: got %q, want %q", got, "/tmp/from-env")
	}

	// t.Setenv above restores the original value after the test, including
	// after this Unsetenv.
	os.Unsetenv("PEM_DIR")
	if got := NewFileCertManager(1).dir; got != "pem" {
		t.Errorf("without PEM_DIR: got %q, want %q", got, "pem")
	}
}

// Full round trip in the target directory: create the CA, load it, issue a
// user certificate. Needs no network.
func TestNewFileCertManagerInDirBootstrapAndLoad(t *testing.T) {
	dir := t.TempDir()

	cm := NewFileCertManagerInDir(0x110, dir)
	if err := cm.BootstrapCa(); err != nil {
		t.Fatalf("BootstrapCa: %v", err)
	}
	if err := cm.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := cm.CreateUser(5); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	for _, name := range []string{
		"ca-cert.pem", "ca-private.pem", "ca-public.pem",
		"5-cert.pem", "5-private.pem", "5-public.pem",
	} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("missing %s in configured dir: %v", name, err)
		}
	}
	if cm.GetCaCertificate() == nil {
		t.Error("CA certificate not loaded")
	}
	if _, err := cm.GetCertificate(5); err != nil {
		t.Errorf("GetCertificate(5): %v", err)
	}
	if _, err := cm.GetPrivkey(5); err != nil {
		t.Errorf("GetPrivkey(5): %v", err)
	}
}
