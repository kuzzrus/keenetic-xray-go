package botcontrol

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestGenerateSelfSignedCert(t *testing.T) {
	cert, err := GenerateSelfSignedCert("test.example.com")
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert: %v", err)
	}
	if len(cert.Certificate) == 0 {
		t.Fatal("cert has no leaf")
	}

	fp, err := FingerprintSHA256(cert)
	if err != nil {
		t.Fatalf("FingerprintSHA256: %v", err)
	}
	if len(fp) != 64 { // hex-encoded SHA256 = 32 bytes = 64 hex chars
		t.Errorf("fingerprint length = %d, want 64", len(fp))
	}
}

func TestGenerateSelfSignedCert_DifferentEachTime(t *testing.T) {
	cert1, err := GenerateSelfSignedCert("a")
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert: %v", err)
	}
	cert2, err := GenerateSelfSignedCert("a")
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert: %v", err)
	}
	fp1, _ := FingerprintSHA256(cert1)
	fp2, _ := FingerprintSHA256(cert2)
	if fp1 == fp2 {
		t.Error("two independently generated certs produced the same fingerprint")
	}
}

func TestFingerprintSHA256_NoLeaf(t *testing.T) {
	if _, err := FingerprintSHA256(tls.Certificate{}); err == nil {
		t.Error("expected error for a certificate with no leaf")
	}
}

func TestLoadOrGenerateCert_GeneratesThenReuses(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "server.crt")
	keyPath := filepath.Join(dir, "server.key")

	cert1, err := LoadOrGenerateCert(certPath, keyPath, "test")
	if err != nil {
		t.Fatalf("LoadOrGenerateCert (generate): %v", err)
	}
	fp1, err := FingerprintSHA256(cert1)
	if err != nil {
		t.Fatalf("FingerprintSHA256: %v", err)
	}

	cert2, err := LoadOrGenerateCert(certPath, keyPath, "test")
	if err != nil {
		t.Fatalf("LoadOrGenerateCert (reload): %v", err)
	}
	fp2, err := FingerprintSHA256(cert2)
	if err != nil {
		t.Fatalf("FingerprintSHA256: %v", err)
	}

	if fp1 != fp2 {
		t.Errorf("fingerprint changed across reload: %s != %s -- would lock out every already-configured agent", fp1, fp2)
	}
}

func TestLoadOrGenerateCert_RefusesPartialPair(t *testing.T) {
	// Losing exactly one half of the pair (a botched restore, a
	// half-applied deploy) must be an error, not a silent regenerate:
	// regenerating mints a new fingerprint and locks out every agent
	// that pinned the old one.
	for _, tc := range []struct {
		name   string
		remove string // "cert" or "key"
	}{
		{"key missing", "key"},
		{"cert missing", "cert"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			certPath := filepath.Join(dir, "server.crt")
			keyPath := filepath.Join(dir, "server.key")

			if _, err := LoadOrGenerateCert(certPath, keyPath, "test"); err != nil {
				t.Fatalf("initial generate: %v", err)
			}

			gone := keyPath
			kept := certPath
			if tc.remove == "cert" {
				gone, kept = certPath, keyPath
			}
			if err := os.Remove(gone); err != nil {
				t.Fatalf("remove %s: %v", tc.remove, err)
			}

			if _, err := LoadOrGenerateCert(certPath, keyPath, "test"); err == nil {
				t.Fatalf("expected an error when %s is missing but the other half is present", tc.remove)
			}
			if fileExists(gone) {
				t.Errorf("%s was regenerated; the call should have refused and left things as-is", tc.remove)
			}
			if !fileExists(kept) {
				t.Errorf("the surviving file was disturbed")
			}
		})
	}
}

func TestLoadOrGenerateCert_KeyFileIsPrivate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file mode bits aren't meaningful on Windows; the daemon only runs on Linux")
	}
	dir := t.TempDir()
	certPath := filepath.Join(dir, "server.crt")
	keyPath := filepath.Join(dir, "server.key")

	if _, err := LoadOrGenerateCert(certPath, keyPath, "test"); err != nil {
		t.Fatalf("LoadOrGenerateCert: %v", err)
	}

	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat key file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("key file mode = %o, want 0600", perm)
	}
}
