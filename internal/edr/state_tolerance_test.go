package edr

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestIncidentLedgerCorruptMovedAside(t *testing.T) {
	s := newTestStore(t)
	p := s.path + ".incidents"
	if err := os.WriteFile(p, []byte("{not json\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	x, err := NewIncidentStore(s)
	if err != nil || x == nil || len(x.entries) != 0 {
		t.Fatalf("want empty store, got %v %v", x, err)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("corrupt file should have been moved aside")
	}
	m, _ := filepath.Glob(p + ".corrupt-*")
	if len(m) != 1 {
		t.Fatalf("want one .corrupt-<unixtime> file, got %v", m)
	}
}

func TestCredentialRegistryCorruptFailsClosedClearly(t *testing.T) {
	p := filepath.Join(t.TempDir(), "agents.json")
	secret := "SECRETHASH"
	if err := os.WriteFile(p, []byte(`{"a": "`+secret), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := OpenCredentialRegistry(p)
	if err == nil || r != nil {
		t.Fatal("corrupt registry must fail closed")
	}
	if !strings.Contains(err.Error(), "refusing to start") || strings.Contains(err.Error(), secret) {
		t.Fatalf("unclear or leaking error: %v", err)
	}
}

func testCAFile(t *testing.T) string {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestServerTLSConfigModes(t *testing.T) {
	ca := testCAFile(t)
	cases := map[string]tls.ClientAuthType{
		"":         tls.RequireAndVerifyClientCert,
		"require":  tls.RequireAndVerifyClientCert,
		"optional": tls.VerifyClientCertIfGiven,
	}
	for mode, want := range cases {
		cfg, err := ServerTLSConfigMode(ca, mode)
		if err != nil || cfg.ClientAuth != want || cfg.ClientCAs == nil {
			t.Fatalf("mode %q: %v %v", mode, cfg, err)
		}
	}
	if cfg, _ := ServerTLSConfig(ca); cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatal("ServerTLSConfig must stay strict")
	}
	if _, err := ServerTLSConfigMode(ca, "bogus"); err == nil {
		t.Fatal("bogus mode must error")
	}
	if cfg, _ := ServerTLSConfigMode("", "optional"); cfg.ClientAuth != tls.NoClientCert {
		t.Fatal("no CA means no client auth")
	}
}
