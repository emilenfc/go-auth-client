package authclient

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ---------------------------------------------------------------------------
// Forgery. These are the tests that must never start passing a bad token.
//
// Each one mints something an attacker could realistically produce and asserts
// it is refused. A regression here does not look like a bug -- every request
// still succeeds -- so there is nothing else to catch it.
// ---------------------------------------------------------------------------

// TestRejectsAlgNone guards the oldest JWT attack there is: strip the
// signature, set "alg":"none", and hope the verifier believes the header.
func TestRejectsAlgNone(t *testing.T) {
	auth := newFakeAuth(t)
	v := auth.verifier(t)

	tok := jwt.NewWithClaims(jwt.SigningMethodNone, auth.claims())
	forged, err := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("build unsigned token: %v", err)
	}

	if _, err := v.Verify(context.Background(), forged); err == nil {
		t.Fatal("an unsigned (alg=none) token was accepted")
	}
}

// TestRejectsTokenSignedWithAnotherKey: a well-formed RS256 token signed by a
// key that is not the auth service's. This is what a compromised downstream
// service would produce if it tried to mint its own tokens.
func TestRejectsTokenSignedWithAnotherKey(t *testing.T) {
	auth := newFakeAuth(t)
	v := auth.verifier(t)

	attackerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate attacker key: %v", err)
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, auth.claims())
	tok.Header["kid"] = auth.kid // claim to be the real key
	forged, err := tok.SignedString(attackerKey)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if _, err := v.Verify(context.Background(), forged); err == nil {
		t.Fatal("a token signed with a foreign key was accepted")
	}
}

// TestRejectsHMACSignedWithPublicKey is the subtle one, and the reason the
// signing method is pinned rather than read from the token.
//
// Under RS256 the verification key is public. If the verifier honoured the
// token's own "alg" header, an attacker could switch it to HS256 and sign with
// the public key as the HMAC secret -- material they have by definition. The
// verifier would then "verify" the signature with the same value and accept it.
func TestRejectsHMACSignedWithPublicKey(t *testing.T) {
	auth := newFakeAuth(t)
	v := auth.verifier(t)

	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, auth.claims())
	tok.Header["kid"] = auth.kid
	forged, err := tok.SignedString(auth.publicKeyPEM(t))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if _, err := v.Verify(context.Background(), forged); err == nil {
		t.Fatal("an HMAC token signed with the public key was accepted (algorithm confusion)")
	}
}

// TestRejectsWrongAudience: a genuine token, correctly signed, but minted for a
// different service. Once one key signs tokens for more than one audience, the
// signature alone stops being enough.
func TestRejectsWrongAudience(t *testing.T) {
	auth := newFakeAuth(t)
	v := auth.verifier(t)

	claims := auth.claims()
	claims["aud"] = []string{"some-other-service"}

	if _, err := v.Verify(context.Background(), auth.signRS256(t, claims)); err == nil {
		t.Fatal("a token minted for another audience was accepted")
	}
}

// TestRejectsWrongIssuer: correctly signed, but not by the identity provider
// this service trusts.
func TestRejectsWrongIssuer(t *testing.T) {
	auth := newFakeAuth(t)
	v := auth.verifier(t)

	claims := auth.claims()
	claims["iss"] = "rogue-idp"

	if _, err := v.Verify(context.Background(), auth.signRS256(t, claims)); err == nil {
		t.Fatal("a token from another issuer was accepted")
	}
}

// TestRejectsExpiredToken, and reports it distinctly so a client knows to
// refresh rather than to sign in again.
func TestRejectsExpiredToken(t *testing.T) {
	auth := newFakeAuth(t)
	v := auth.verifier(t)

	claims := auth.claims()
	// Well past the default 30s leeway.
	claims["iat"] = time.Now().Add(-2 * time.Hour).Unix()
	claims["exp"] = time.Now().Add(-time.Hour).Unix()

	_, err := v.Verify(context.Background(), auth.signRS256(t, claims))
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("Verify(expired) = %v, want ErrExpired", err)
	}
}

// TestRejectsUnknownKeyID: correctly signed, but naming a key the auth service
// does not publish.
func TestRejectsUnknownKeyID(t *testing.T) {
	auth := newFakeAuth(t)
	v := auth.verifier(t)

	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, auth.claims())
	tok.Header["kid"] = "a-key-that-does-not-exist"
	signed, err := tok.SignedString(auth.key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if _, err := v.Verify(context.Background(), signed); err == nil {
		t.Fatal("a token naming an unpublished key was accepted")
	}
}

func TestRejectsGarbage(t *testing.T) {
	auth := newFakeAuth(t)
	v := auth.verifier(t)

	for _, token := range []string{"", "not.a.token", "a.b.c", "Bearer xyz"} {
		if _, err := v.Verify(context.Background(), token); err == nil {
			t.Errorf("Verify(%q) accepted a malformed token", token)
		}
	}
}

// ---------------------------------------------------------------------------
// The happy path
// ---------------------------------------------------------------------------

func TestVerifyReturnsTheCallersIdentity(t *testing.T) {
	auth := newFakeAuth(t)
	v := auth.verifier(t)

	identity, err := v.Verify(context.Background(), auth.signRS256(t, auth.claims()))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	if identity.UserID != "11111111-2222-3333-4444-555555555555" {
		t.Errorf("UserID = %q", identity.UserID)
	}
	if identity.Email != "ada@example.com" {
		t.Errorf("Email = %q", identity.Email)
	}
	if identity.PhoneNumber != "+250788123456" {
		t.Errorf("PhoneNumber = %q", identity.PhoneNumber)
	}
	if identity.TokenVersion != 3 {
		t.Errorf("TokenVersion = %d, want 3", identity.TokenVersion)
	}
	if !identity.Can("orders:read") || !identity.Can("users:read") {
		t.Errorf("permissions = %v, want both granted", identity.Permissions)
	}
	if identity.Can("orders:delete") {
		t.Error("identity holds a permission the token did not grant")
	}
	if !identity.HasRole("order_reader") || identity.HasRole("admin") {
		t.Errorf("roles = %v", identity.Roles)
	}
	if identity.ExpiresAt.IsZero() {
		t.Error("ExpiresAt was not populated")
	}
}

func TestPermissionSetHelpers(t *testing.T) {
	set := PermissionSet{"a": {}, "b": {}}

	if !set.HasAny("x", "b") || set.HasAny("x", "y") {
		t.Error("HasAny is wrong")
	}
	if !set.HasAll("a", "b") || set.HasAll("a", "x") {
		t.Error("HasAll is wrong")
	}
}

// ---------------------------------------------------------------------------
// Discovery and configuration
// ---------------------------------------------------------------------------

func TestDiscoveryFillsInTheConfiguration(t *testing.T) {
	auth := newFakeAuth(t)

	v, err := New(Config{AuthURL: auth.server.URL})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if v.cfg.Issuer != auth.issuer || v.cfg.Audience != auth.audience {
		t.Errorf("discovered issuer/audience = %q/%q", v.cfg.Issuer, v.cfg.Audience)
	}
	if v.cfg.JWKSURL == "" {
		t.Error("JWKS URL was not discovered")
	}
}

// TestExplicitConfigurationWinsOverDiscovery: a caller who pins the issuer
// wants it pinned, not replaced by whatever the endpoint reports.
func TestExplicitConfigurationWinsOverDiscovery(t *testing.T) {
	auth := newFakeAuth(t)

	v, err := New(Config{
		AuthURL:  auth.server.URL,
		Issuer:   "pinned-issuer",
		Audience: "pinned-audience",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if v.cfg.Issuer != "pinned-issuer" || v.cfg.Audience != "pinned-audience" {
		t.Errorf("discovery overrode explicit configuration: %q/%q", v.cfg.Issuer, v.cfg.Audience)
	}
	// A token from the real service should now be refused, because the pinned
	// values are what count.
	if _, err := v.Verify(context.Background(), auth.signRS256(t, auth.claims())); err == nil {
		t.Error("pinned issuer/audience were not enforced")
	}
}

func TestNewRequiresSomewhereToGetKeys(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Error("New accepted a configuration with no AuthURL, JWKSURL or PublicKey")
	}
}

// TestUnreachableAuthServiceFailsAtStartup: a service that cannot verify
// anything should refuse to start rather than serve 401s.
func TestUnreachableAuthServiceFailsAtStartup(t *testing.T) {
	// Port 1 is reserved and nothing listens there.
	if _, err := New(Config{AuthURL: "http://127.0.0.1:1"}); err == nil {
		t.Error("New succeeded against an unreachable auth service")
	}
}

// ---------------------------------------------------------------------------
// The claim contract, which is what stops the two repositories drifting apart
// ---------------------------------------------------------------------------

func TestRejectsAuthServiceMissingARequiredClaim(t *testing.T) {
	auth := newFakeAuth(t)
	// The server renamed "permissions" to "scopes".
	auth.claimsSupported = []string{"sub", "email", "roles", "scopes", "exp"}

	_, err := New(Config{AuthURL: auth.server.URL})
	if err == nil {
		t.Fatal("New accepted an auth service that no longer advertises \"permissions\"")
	}
	// The message has to name what is missing, or nobody can act on it.
	if !contains(err.Error(), "permissions") {
		t.Errorf("error does not name the missing claim: %v", err)
	}
}

// TestAcceptsAuthServiceWithoutAClaimList keeps older deployments working.
func TestAcceptsAuthServiceWithoutAClaimList(t *testing.T) {
	auth := newFakeAuth(t)
	auth.claimsSupported = nil

	if _, err := New(Config{AuthURL: auth.server.URL}); err != nil {
		t.Fatalf("New rejected an auth service that advertises no claim list: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Key caching
// ---------------------------------------------------------------------------

// TestKeysAreFetchedOnce: verifying many tokens must not hammer the auth
// service's JWKS endpoint.
func TestKeysAreFetchedOnce(t *testing.T) {
	auth := newFakeAuth(t)
	v := auth.verifier(t)

	for i := 0; i < 10; i++ {
		if _, err := v.Verify(context.Background(), auth.signRS256(t, auth.claims())); err != nil {
			t.Fatalf("Verify: %v", err)
		}
	}

	if hits := auth.jwksHits.Load(); hits != 1 {
		t.Errorf("fetched the key set %d times for 10 verifications, want 1", hits)
	}
}

// TestUnknownKeyIDTriggersARefresh: this is what makes key rotation work
// without redeploying every service.
//
// MinRefreshInterval is disabled here so the rotation is observed immediately;
// TestUnknownKeyIDRefreshIsThrottled covers the throttle itself.
func TestUnknownKeyIDTriggersARefresh(t *testing.T) {
	auth := newFakeAuth(t)

	v, err := New(Config{AuthURL: auth.server.URL, MinRefreshInterval: -1})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Prime the cache with the original key.
	if _, err := v.Verify(context.Background(), auth.signRS256(t, auth.claims())); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	before := auth.jwksHits.Load()

	// The auth service rotates: new key, new id.
	rotated, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rotated key: %v", err)
	}
	auth.key, auth.kid = rotated, "test-key-2"

	if _, err := v.Verify(context.Background(), auth.signRS256(t, auth.claims())); err != nil {
		t.Fatalf("a token signed with the rotated key was rejected: %v", err)
	}
	if auth.jwksHits.Load() <= before {
		t.Error("an unknown key id did not trigger a key-set refresh")
	}
}

// TestUnknownKeyIDRefreshIsThrottled: a stream of tokens carrying invented key
// ids must not turn this service into a load generator against the auth
// service.
func TestUnknownKeyIDRefreshIsThrottled(t *testing.T) {
	auth := newFakeAuth(t)

	v, err := New(Config{AuthURL: auth.server.URL, MinRefreshInterval: time.Hour})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Prime the cache.
	if _, err := v.Verify(context.Background(), auth.signRS256(t, auth.claims())); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	before := auth.jwksHits.Load()

	for i := 0; i < 20; i++ {
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, auth.claims())
		tok.Header["kid"] = "invented-key-" + string(rune('a'+i))
		signed, err := tok.SignedString(auth.key)
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		if _, err := v.Verify(context.Background(), signed); err == nil {
			t.Fatal("a token naming an unpublished key was accepted")
		}
	}

	if after := auth.jwksHits.Load(); after != before {
		t.Errorf("20 tokens with invented key ids caused %d key-set fetches, want 0",
			after-before)
	}
}

func contains(haystack, needle string) bool {
	return len(needle) > 0 && len(haystack) >= len(needle) &&
		(haystack == needle || indexOf(haystack, needle) >= 0)
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}

func TestPhoneNumberIsOptional(t *testing.T) {
	auth := newFakeAuth(t)
	v := auth.verifier(t)

	claims := auth.claims()
	delete(claims, "phone_number")

	identity, err := v.Verify(context.Background(), auth.signRS256(t, claims))
	if err != nil {
		t.Fatalf("a token without phone_number was rejected: %v", err)
	}
	if identity.PhoneNumber != "" {
		t.Errorf("PhoneNumber = %q, want empty", identity.PhoneNumber)
	}
}
