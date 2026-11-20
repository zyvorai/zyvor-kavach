package licence

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

var now = time.Unix(1_800_000_000, 0)

func mint(t *testing.T, priv ed25519.PrivateKey, product, edition string, expires int64) string {
	t.Helper()
	raw, _ := json.Marshal(map[string]any{"v": 1, "product": product, "edition": edition, "id": "t", "licensee": "x", "email": "x@example.com", "macs": 3, "issued": 0, "expires": expires})
	e := base64.RawURLEncoding
	return "ZYV1." + e.EncodeToString(raw) + "." + e.EncodeToString(ed25519.Sign(priv, raw))
}

func TestEmbeddedKeyIsValid(t *testing.T) { _ = embedded() }

func TestStates(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader) // throwaway: the real signing key is never here
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	trial := mint(t, priv, "kavach", "trial", now.Unix()+5*day)
	if s := Evaluate(trial, now, pub); s.State != Trial || *s.DaysLeft != 5 || s.Enforcement != "soft" {
		t.Fatalf("trial: %+v", s)
	}
	if s := Evaluate(mint(t, priv, "kavach", "pro", now.Unix()+10*day), now, pub); s.State != Licensed || *s.Endpoints != 3 {
		t.Fatalf("pro: %+v", s)
	}
	if s := Evaluate(mint(t, priv, "kavach", "trial", now.Unix()-1), now, pub); s.State != LicenceExpired || *s.DaysLeft != 0 {
		t.Fatalf("expired: %+v", s)
	}
	if s := Evaluate(mint(t, priv, "velora", "pro", now.Unix()+day), now, pub); s.State != Invalid {
		t.Fatalf("wrong product: %+v", s)
	}
	if s := Evaluate(mint(t, other, "kavach", "pro", now.Unix()+day), now, pub); s.State != Invalid {
		t.Fatalf("wrong signer: %+v", s)
	}
	if s := Evaluate(trial+"A", now, pub); s.State != Invalid {
		t.Fatalf("tampered signature: %+v", s)
	}
	raw := []byte(`{"v":1,"product":"kavach","edition":"pro","macs":9,"expires":9999999999}`)
	sig := ed25519.Sign(priv, []byte(`{"v":1,"product":"kavach","edition":"trial","macs":3,"expires":1800000100}`))
	forged := "ZYV1." + base64.RawURLEncoding.EncodeToString(raw) + "." + base64.RawURLEncoding.EncodeToString(sig)
	if s := Evaluate(forged, now, pub); s.State != Invalid {
		t.Fatalf("tampered payload: %+v", s)
	}
	if s := Evaluate("garbage", now, pub); s.State != Invalid {
		t.Fatalf("garbage: %+v", s)
	}
	if s := Evaluate("  ", now, pub); s.State != Unlicensed {
		t.Fatalf("no key: %+v", s)
	}
}
