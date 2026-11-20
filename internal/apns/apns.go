// Package apns sends notifications through Apple's push notification service (APNs), with
// token-based authentication: an ES256 provider token signed with a .p8 key from the Apple
// developer account. It uses only the standard library. Go's net/http speaks HTTP/2 over
// TLS, which APNs requires.
//
// Push notifications are a rerouted feature for the Reroute app, outside the Tieroute spec.
package apns

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"
)

// Environments a device token belongs to: a development build of the app gets sandbox
// tokens, and a TestFlight or App Store build gets production ones.
const (
	Sandbox    = "sandbox"
	Production = "production"
)

// Apple's servers for each environment.
var appleHosts = map[string]string{
	Sandbox:    "https://api.sandbox.push.apple.com",
	Production: "https://api.push.apple.com",
}

// tokenRefresh is how long a provider token is used. Apple accepts one for an hour, and
// refuses new ones more often than every 20 minutes.
const tokenRefresh = 50 * time.Minute

// LoadKey reads a token-signing key: a .p8 file, which is a PEM-encoded PKCS #8 EC P-256
// private key.
func LoadKey(path string) (*ecdsa.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseKey(b)
}

// ParseKey parses a .p8 key's contents.
func ParseKey(b []byte) (*ecdsa.PrivateKey, error) {
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("not a PEM file: expected a .p8 key starting with -----BEGIN PRIVATE KEY-----")
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("not a PKCS #8 private key: %w", err)
	}
	ek, ok := k.(*ecdsa.PrivateKey)
	if !ok || ek.Curve != elliptic.P256() {
		return nil, errors.New("not an EC P-256 key: APNs signs with ES256")
	}
	return ek, nil
}

// ProviderToken makes an APNs provider token: a JWT with header {"alg":"ES256","kid":keyID}
// and claims {"iss":teamID,"iat":iat}, signed with ES256 (r and s, 32 bytes each).
func ProviderToken(key *ecdsa.PrivateKey, keyID, teamID string, iat time.Time) (string, error) {
	enc := base64.RawURLEncoding
	h, _ := json.Marshal(map[string]string{"alg": "ES256", "kid": keyID})
	c, _ := json.Marshal(map[string]any{"iss": teamID, "iat": iat.Unix()})
	signing := enc.EncodeToString(h) + "." + enc.EncodeToString(c)
	sum := sha256.Sum256([]byte(signing))
	r, s, err := ecdsa.Sign(rand.Reader, key, sum[:])
	if err != nil {
		return "", err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return signing + "." + enc.EncodeToString(sig), nil
}

// Client sends notifications for one app (its topic, the bundle ID) with one key.
type Client struct {
	key    *ecdsa.PrivateKey
	keyID  string
	teamID string
	topic  string
	http   *http.Client
	hosts  map[string]string

	mu    sync.Mutex
	tok   string
	tokAt time.Time
}

// New makes a client. Requests time out after 15 seconds, and go through the proxy that
// HTTPS_PROXY names, if any.
func New(key *ecdsa.PrivateKey, keyID, teamID, topic string) *Client {
	return &Client{
		key: key, keyID: keyID, teamID: teamID, topic: topic, hosts: appleHosts,
		http: &http.Client{
			Timeout:   15 * time.Second,
			Transport: &http.Transport{Proxy: http.ProxyFromEnvironment, ForceAttemptHTTP2: true, MaxIdleConnsPerHost: 4, IdleConnTimeout: 5 * time.Minute, TLSHandshakeTimeout: 10 * time.Second},
		},
	}
}

// UseServer sends every environment's notifications to origin through hc instead of to
// Apple. For tests only.
func (c *Client) UseServer(origin string, hc *http.Client) {
	c.hosts = map[string]string{Sandbox: origin, Production: origin}
	c.http = hc
}

// Topic is the app's bundle ID.
func (c *Client) Topic() string { return c.topic }

// providerToken returns the cached provider token, or a new one once it's tokenRefresh old.
func (c *Client) providerToken(force bool) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.tok != "" && !force && time.Since(c.tokAt) < tokenRefresh {
		return c.tok, nil
	}
	t, err := ProviderToken(c.key, c.keyID, c.teamID, time.Now())
	if err != nil {
		return "", err
	}
	c.tok, c.tokAt = t, time.Now()
	return t, nil
}

// Notification is one push to one device.
type Notification struct {
	Token      string    // the device token, in hex
	Env        string    // Sandbox or Production
	Payload    []byte    // the JSON payload, with its "aps" dictionary
	PushType   string    // apns-push-type, such as "alert"
	Priority   int       // apns-priority: 10 sends it at once, 5 when convenient
	CollapseID string    // apns-collapse-id: a newer notification with the same one replaces it
	Expiration time.Time // apns-expiration: how long APNs keeps trying an offline device
}

// Result is APNs's answer.
type Result struct {
	Status int
	Reason string // the "reason" in an error body, such as BadDeviceToken
}

// OK reports whether APNs accepted the notification.
func (r Result) OK() bool { return r.Status == http.StatusOK }

// TokenGone reports whether the device token will never work again for this app: the app
// was removed (410), or the token is malformed or for another app or environment.
func (r Result) TokenGone() bool {
	return r.Status == http.StatusGone ||
		r.Status == http.StatusBadRequest && (r.Reason == "BadDeviceToken" || r.Reason == "DeviceTokenNotForTopic")
}

// Send sends one notification. An error means no answer came back; a refusal is a Result.
func (c *Client) Send(ctx context.Context, n Notification) (Result, error) {
	host, ok := c.hosts[n.Env]
	if !ok {
		return Result{}, fmt.Errorf("unknown APNs environment %q", n.Env)
	}
	res, err := c.send(ctx, host, n, false)
	if err == nil && res.Status == http.StatusForbidden && res.Reason == "ExpiredProviderToken" {
		res, err = c.send(ctx, host, n, true) // once, with a new token
	}
	return res, err
}

func (c *Client) send(ctx context.Context, host string, n Notification, newToken bool) (Result, error) {
	tok, err := c.providerToken(newToken)
	if err != nil {
		return Result{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, host+"/3/device/"+n.Token, bytes.NewReader(n.Payload))
	if err != nil {
		return Result{}, err
	}
	h := req.Header
	h.Set("authorization", "bearer "+tok)
	h.Set("apns-topic", c.topic)
	h.Set("content-type", "application/json")
	if n.PushType != "" {
		h.Set("apns-push-type", n.PushType)
	}
	if n.Priority != 0 {
		h.Set("apns-priority", strconv.Itoa(n.Priority))
	}
	if n.CollapseID != "" {
		h.Set("apns-collapse-id", n.CollapseID)
	}
	if !n.Expiration.IsZero() {
		h.Set("apns-expiration", strconv.FormatInt(n.Expiration.Unix(), 10))
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return Result{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	res := Result{Status: resp.StatusCode}
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Reason string `json:"reason"`
		}
		json.Unmarshal(body, &e)
		res.Reason = e.Reason
	}
	return res, nil
}
