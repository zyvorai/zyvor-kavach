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

// ServerTLSConfig enables optional verification of enrolled client certificate
// identities. Enrollment bearer tokens remain necessary; certificate identity
// mapping and automated CA issuance are outside this milestone.
func ServerTLSConfig(caPath string) (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if caPath != "" {
		b, err := os.ReadFile(caPath)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(b) {
			return nil, errors.New("invalid client CA bundle")
		}
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
		cfg.ClientCAs = pool
	}
	return cfg, nil
}
