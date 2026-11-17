package edr

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"os"
	"time"
)

// NewMutualTLSClient validates the server trust chain and supplies a client
// certificate when configured. It deliberately never enables InsecureSkipVerify.
func NewMutualTLSClient(caPath, certPath, keyPath string) (*http.Client, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if (certPath == "") != (keyPath == "") {
		return nil, errors.New("client certificate and key must both be supplied")
	}
	if caPath != "" {
		b, err := os.ReadFile(caPath)
		if err != nil {
			return nil, err
		}
		roots, err := x509.SystemCertPool()
		if err != nil || roots == nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(b) {
			return nil, errors.New("invalid CA bundle")
		}
		tlsConfig.RootCAs = roots
	}
	if certPath != "" {
		pair, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return nil, err
		}
		tlsConfig.Certificates = []tls.Certificate{pair}
	}
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsConfig}}, nil
}

// Client certificate modes for ServerTLSConfigMode.
const (
	ClientAuthRequire  = "require"  // handshake fails without a verified client certificate
	ClientAuthOptional = "optional" // certificate verified only when presented; none is accepted
)

// ServerTLSConfig is the strict form: with a client CA every client must present a
// verified certificate.
func ServerTLSConfig(caPath string) (*tls.Config, error) {
	return ServerTLSConfigMode(caPath, ClientAuthRequire)
}

// ServerTLSConfigMode configures client certificate verification. "require" (default
// when empty) uses RequireAndVerifyClientCert. "optional" uses VerifyClientCertIfGiven:
// clients without a certificate (kubelet probes, kavachctl, browsers) still connect,
// but a certificate that is presented must verify against the CA. Bearer tokens remain
// mandatory in both modes; mode has no effect without a CA.
func ServerTLSConfigMode(caPath, mode string) (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if caPath != "" {
		var auth tls.ClientAuthType
		switch mode {
		case "", ClientAuthRequire:
			auth = tls.RequireAndVerifyClientCert
		case ClientAuthOptional:
			auth = tls.VerifyClientCertIfGiven
		default:
			return nil, errors.New("invalid client auth mode " + mode + " (want require or optional)")
		}
		b, err := os.ReadFile(caPath)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(b) {
			return nil, errors.New("invalid client CA bundle")
		}
		cfg.ClientAuth = auth
		cfg.ClientCAs = pool
	}
	return cfg, nil
}
