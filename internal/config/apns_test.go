package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeP8(t *testing.T, curve elliptic.Curve) string {
	t.Helper()
	k, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(k)
	p := filepath.Join(t.TempDir(), "AuthKey_TEST.p8")
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// Push is off without a key file, and with one, the key and both IDs are checked at the
// start.
func TestAPNSSettings(t *testing.T) {
	load := func(extra string) (*Config, error) {
		lookup := func(k string) (string, bool) {
			for _, line := range strings.Split(baseEnv+extra, "\n") {
				if key, v, ok := strings.Cut(line, "="); ok && key == k {
					return v, true
				}
			}
			return "", false
		}
		c, err := parse(lookup)
		if err != nil {
			return nil, err
		}
		return c, c.finish()
	}
	c, err := load("")
	if err != nil || c.APNSKey() != nil || c.APNSTopic != DefaultAPNSTopic {
		t.Fatalf("no key file: %v %v %q", err, c.APNSKey(), c.APNSTopic)
	}
	good := writeP8(t, elliptic.P256())
	c, err = load("REROUTED_APNS_KEY_FILE=" + good + "\nREROUTED_APNS_KEY_ID=ABC123DEFG\nREROUTED_APNS_TEAM_ID=TEAM123456\n")
	if err != nil || c.APNSKey() == nil {
		t.Fatalf("a good key: %v", err)
	}
	for name, extra := range map[string]string{
		"missing file":  "REROUTED_APNS_KEY_FILE=" + filepath.Join(t.TempDir(), "none.p8") + "\nREROUTED_APNS_KEY_ID=ABC123DEFG\nREROUTED_APNS_TEAM_ID=TEAM123456\n",
		"P-384 key":     "REROUTED_APNS_KEY_FILE=" + writeP8(t, elliptic.P384()) + "\nREROUTED_APNS_KEY_ID=ABC123DEFG\nREROUTED_APNS_TEAM_ID=TEAM123456\n",
		"no key ID":     "REROUTED_APNS_KEY_FILE=" + good + "\nREROUTED_APNS_TEAM_ID=TEAM123456\n",
		"short key ID":  "REROUTED_APNS_KEY_FILE=" + good + "\nREROUTED_APNS_KEY_ID=ABC123\nREROUTED_APNS_TEAM_ID=TEAM123456\n",
		"long team ID":  "REROUTED_APNS_KEY_FILE=" + good + "\nREROUTED_APNS_KEY_ID=ABC123DEFG\nREROUTED_APNS_TEAM_ID=TEAM1234567\n",
		"spaced topic":  "REROUTED_APNS_KEY_FILE=" + good + "\nREROUTED_APNS_KEY_ID=ABC123DEFG\nREROUTED_APNS_TEAM_ID=TEAM123456\nREROUTED_APNS_TOPIC=a b\n",
		"empty topic":   "REROUTED_APNS_KEY_FILE=" + good + "\nREROUTED_APNS_KEY_ID=ABC123DEFG\nREROUTED_APNS_TEAM_ID=TEAM123456\nREROUTED_APNS_TOPIC=\n",
		"punctuated ID": "REROUTED_APNS_KEY_FILE=" + good + "\nREROUTED_APNS_KEY_ID=ABC-23DEFG\nREROUTED_APNS_TEAM_ID=TEAM123456\n",
	} {
		if _, err := load(extra); err == nil || !strings.Contains(err.Error(), "REROUTED_APNS_") {
			t.Errorf("%s: %v", name, err)
		}
	}
}
