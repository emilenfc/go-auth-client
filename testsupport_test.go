package authclient

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// fakeAuth is a stand-in for the auth service: it signs tokens with a real RSA
// key and serves the discovery and JWKS documents a Verifier reads.
//
// Everything the tests need to attack is therefore under their control -- the
// key, the claims, the advertised contract -- without a database or a running
// server.
type fakeAuth struct {
	key      *rsa.PrivateKey
	kid      string
	issuer   string
	audience string
	// claimsSupported is what the discovery document advertises. Empty means
	// the field is omitted, as an older auth service would.
	claimsSupported []string
	server          *httptest.Server
	// jwksHits counts key-set fetches, so tests can assert caching.
	jwksHits atomic.Int32
}

func newFakeAuth(t *testing.T) *fakeAuth {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	f := &fakeAuth{
		key:             key,
		kid:             "test-key-1",
		issuer:          "test-issuer",
		audience:        "test-audience",
		claimsSupported: []string{"sub", "email", "roles", "permissions", "exp"},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		doc := map[string]any{
			"issuer":   f.issuer,
			"audience": f.audience,
			"jwks_uri": f.server.URL + "/.well-known/jwks.json",
		}
		if len(f.claimsSupported) > 0 {
			doc["claims_supported"] = f.claimsSupported
		}
		writeJSON(w, doc)
	})
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		f.jwksHits.Add(1)
		writeJSON(w, map[string]any{"keys": []any{jwkFor(&f.key.PublicKey, f.kid)}})
	})

	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)
	return f
}

// verifier returns a Verifier pointed at this fake auth service.
func (f *fakeAuth) verifier(t *testing.T) *Verifier {
	t.Helper()

	v, err := New(Config{AuthURL: f.server.URL})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return v
}

// claims returns a valid claim set, which individual tests then spoil.
func (f *fakeAuth) claims() jwt.MapClaims {
	now := time.Now()
	return jwt.MapClaims{
		"sub":           "11111111-2222-3333-4444-555555555555",
		"email":         "ada@example.com",
		"roles":         []string{"user", "order_reader"},
		"permissions":   []string{"orders:read", "users:read"},
		"token_version": 3,
		"iss":           f.issuer,
		"aud":           []string{f.audience},
		"iat":           now.Unix(),
		"exp":           now.Add(time.Hour).Unix(),
	}
}

// signRS256 mints a token with this service's real key.
func (f *fakeAuth) signRS256(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()

	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = f.kid

	signed, err := tok.SignedString(f.key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signed
}

// publicKeyPEM is what an attacker can trivially obtain -- it is published.
func (f *fakeAuth) publicKeyPEM(t *testing.T) []byte {
	t.Helper()

	der, err := x509.MarshalPKIXPublicKey(&f.key.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func jwkFor(pub *rsa.PublicKey, kid string) map[string]any {
	return map[string]any{
		"kty": "RSA",
		"use": "sig",
		"alg": "RS256",
		"kid": kid,
		"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}
