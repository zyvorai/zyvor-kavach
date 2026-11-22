// Package licence reports the soft licence status of Kavach.
//
// Key format (shared by every Zyvor product):
//
//	ZYV1.<b64url payload JSON>.<b64url Ed25519 signature over the payload bytes>
//
// This package only VERIFIES. Keys are issued by Zyvor and no signing key is in this repository.
//
// Enforcement is soft: the status is information only. Nothing in Kavach is ever disabled, limited or deleted because a
// trial or licence ended, or because there is no key. A 30-day trial key (edition "trial") applies to the paid
// production licence and support.
//
// Key source: KAVACH_LICENCE_KEY, else the file named by KAVACH_LICENCE_FILE, else ./data/licence.key, else /etc/kavach/licence.key.
package licence

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// PublicKey is the same text as zyvor-licensing/public-keys/kavach.pub.
const PublicKey = "IABU3vJc11_w68h8r0LygnYaKdoPVqtkU-EHQt5cN6Q"

// Product is the product id a key must carry.
const Product = "kavach"

// States reported by Evaluate.
const (
	Licensed       = "licensed"
	Trial          = "trial"
	LicenceExpired = "licence_expired"
	Unlicensed     = "unlicensed"
	Invalid        = "invalid"
)

const day = 24 * 60 * 60

type payload struct {
	V       int    `json:"v"`
	Product string `json:"product"`
	Edition string `json:"edition"`
	Macs    int    `json:"macs"`
	Expires int64  `json:"expires"`
}

// Status is the JSON-safe licence status.
type Status struct {
	Product     string  `json:"product"`
	State       string  `json:"state"`
	Edition     *string `json:"edition"`
	DaysLeft    *int64  `json:"days_left"`
	Endpoints   *int    `json:"endpoints"`
	Enforcement string  `json:"enforcement"`
	Message     string  `json:"message"`
}

func b64(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}

func parse(key string, pub ed25519.PublicKey) (*payload, string) {
	parts := strings.Split(strings.TrimSpace(key), ".")
	if len(parts) != 3 || parts[0] != "ZYV1" {
		return nil, "not a Zyvor licence key"
	}
	raw, err1 := b64(parts[1])
	sig, err2 := b64(parts[2])
	if err1 != nil || err2 != nil {
		return nil, "bad key encoding"
	}
	if len(sig) != ed25519.SignatureSize || !ed25519.Verify(pub, raw, sig) {
		return nil, "signature does not verify"
	}
	var p payload
	if json.Unmarshal(raw, &p) != nil {
		return nil, "bad key payload"
	}
	if p.V != 1 || p.Product != Product {
		return nil, "key is for a different product"
	}
	return &p, ""
}

// Evaluate computes the status for key (empty means none) at time now using pub. It never fails and never gates anything.
func Evaluate(key string, now time.Time, pub ed25519.PublicKey) Status {
	st := Status{Product: Product, Enforcement: "soft"}
	if strings.TrimSpace(key) == "" {
		st.State = Unlicensed
		st.Message = "No licence key. Kavach keeps working; a 30-day trial key for the paid production licence and support is available from sales@zyvor.dev."
		return st
	}
	p, why := parse(key, pub)
	if p == nil {
		st.State = Invalid
		st.Message = fmt.Sprintf("Licence key not accepted (%s). Kavach keeps working.", why)
		return st
	}
	left := (p.Expires - now.Unix()) / day
	if p.Expires-now.Unix() < 0 {
		left = 0
	}
	ed, ep := p.Edition, p.Macs
	st.Edition, st.DaysLeft, st.Endpoints = &ed, &left, &ep
	switch {
	case now.Unix() >= p.Expires:
		st.State = LicenceExpired
		st.Message = "Licence ended. Kavach keeps working; contact sales@zyvor.dev to renew."
	case p.Edition == "trial":
		st.State = Trial
		st.Message = fmt.Sprintf("30-day trial key, %d day(s) left. Nothing is disabled when it ends.", left)
	default:
		st.State = Licensed
		st.Message = fmt.Sprintf("Licensed, %d day(s) left.", left)
	}
	return st
}

func embedded() ed25519.PublicKey {
	raw, err := b64(PublicKey)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		panic("licence: embedded public key is invalid")
	}
	return ed25519.PublicKey(raw)
}

func loadKey() string {
	if k := strings.TrimSpace(os.Getenv("KAVACH_LICENCE_KEY")); k != "" {
		return k
	}
	paths := []string{"./data/licence.key", "/etc/kavach/licence.key"}
	if p := os.Getenv("KAVACH_LICENCE_FILE"); p != "" {
		paths = []string{p}
	}
	for _, p := range paths {
		if b, err := os.ReadFile(p); err == nil && strings.TrimSpace(string(b)) != "" {
			return string(b)
		}
	}
	return ""
}

// Current returns the status from the environment and files.
func Current() Status { return Evaluate(loadKey(), time.Now(), embedded()) }
