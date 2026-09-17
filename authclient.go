// Package authclient verifies access tokens issued by the auth service.
//
// Import it from every other service in the estate. It does the one thing a
// downstream service needs -- decide whether this caller may do this -- without
// a network call on the request path:
//
//	verifier, err := authclient.New(authclient.Config{
//	    JWKSURL:  "https://auth.internal/.well-known/jwks.json",
//	    Issuer:   "go-auth-starter",
//	    Audience: "go-auth-starter-api",
//	})
//
//	orders := r.Group("/orders", verifier.Authenticate())
//	orders.GET("", authclient.RequirePermission("orders:read"), h.List)
//
// The token carries the caller's roles and permissions, signed. Verifying a
// signature is local arithmetic, so authorising a request costs no round trip
// to the auth service and no database query.
//
// It deliberately does not import the auth service's internal packages: a
// client should not depend on the server's domain model, and this package must
// stay importable from any module.
package authclient

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Errors a caller may want to distinguish.
var (
	// ErrExpired means the token was well formed but is past its lifetime. The
	// client should refresh and retry.
	ErrExpired = errors.New("access token has expired")
	// ErrInvalid means the token was malformed, forged, or minted for someone
	// else. The client should sign in again.
	ErrInvalid = errors.New("access token is invalid")
)

// Identity is the authenticated caller, reconstructed from a verified token.
type Identity struct {
	UserID       string
	Email        string
	Roles        []string
	Permissions  PermissionSet
	TokenVersion int
	// ExpiresAt is when this token stops being accepted. Anything the caller
	// was authorised for is only known to be true until then.
	ExpiresAt time.Time
}

// Can reports whether the caller holds a permission.
func (i *Identity) Can(permission string) bool { return i.Permissions.Has(permission) }

// HasRole reports whether the caller holds a role. Prefer Can: a permission
// check keeps working when someone introduces a new role that should also pass.
func (i *Identity) HasRole(role string) bool {
	for _, r := range i.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// PermissionSet is a deduplicated set of permission names.
type PermissionSet map[string]struct{}

// Has reports whether the set contains the permission.
func (s PermissionSet) Has(name string) bool { _, ok := s[name]; return ok }

// HasAny reports whether the set contains at least one of the permissions.
func (s PermissionSet) HasAny(names ...string) bool {
	for _, n := range names {
		if s.Has(n) {
			return true
		}
	}
	return false
}

// HasAll reports whether the set contains every permission.
func (s PermissionSet) HasAll(names ...string) bool {
	for _, n := range names {
		if !s.Has(n) {
			return false
		}
	}
	return true
}

// claims mirrors the auth service's token payload.
type claims struct {
	jwt.RegisteredClaims
	Email        string   `json:"email"`
	Roles        []string `json:"roles"`
	Permissions  []string `json:"permissions"`
	TokenVersion int      `json:"token_version"`
}

// Config configures a Verifier.
//
// The short form is one setting:
//
//	authclient.New(authclient.Config{AuthURL: "http://auth.internal:8080"})
//
// which reads the issuer, audience and key location from the auth service's
// discovery document. Set any of them explicitly to override what discovery
// reports.
type Config struct {
	// AuthURL is the auth service's base URL, e.g. http://auth.internal:8080.
	//
	// When set, the issuer, audience and JWKS location are read from
	// <AuthURL>/.well-known/openid-configuration at startup, so a downstream
	// service needs one setting instead of three -- and cannot get them
	// subtly wrong, which rejects every token with a 401 that looks like
	// nothing is broken.
	AuthURL string

	// JWKSURL is the auth service's key set, e.g.
	// https://auth.internal/.well-known/jwks.json. Discovered from AuthURL
	// when not set.
	JWKSURL string
	// PublicKey verifies RS256 tokens without fetching a key set. Use it when
	// the key is delivered by configuration rather than over the network.
	PublicKey *rsa.PublicKey

	// Issuer and Audience must match what the auth service puts in its tokens
	// (JWT_ISSUER and JWT_AUDIENCE). Discovered from AuthURL when not set.
	//
	// They are checked on every token because a valid signature proves only
	// that this key signed it -- not who minted it, nor who it was for. Once
	// the same key signs tokens for more than one audience (a partner API, a
	// narrower scope), the signature alone stops being enough.
	Issuer   string
	Audience string

	// HTTPClient fetches the key set. Defaults to a client with a 10s timeout.
	HTTPClient *http.Client
	// CacheTTL is how long a fetched key set is reused. Defaults to one hour.
	// An unknown kid triggers a refresh regardless, so a key rotation is picked
	// up without waiting for this to lapse.
	CacheTTL time.Duration
	// Leeway tolerates small clock differences between services. Defaults to
	// 30 seconds; without it a machine a few seconds fast rejects tokens that
	// have only just been issued.
	Leeway time.Duration
	// MinRefreshInterval is the shortest gap between two key-set fetches
	// triggered by an unknown key id. Defaults to one minute.
	//
	// Without it, a token carrying a made-up kid would cause a fetch on every
	// request, letting anyone turn this service into a load generator against
	// the auth service. The cost is that a key rotation can take up to this
	// long to be picked up.
	MinRefreshInterval time.Duration
}

// Verifier validates access tokens.
//
// Safe for concurrent use. Create one per process and share it.
type Verifier struct {
	cfg Config

	mu        sync.RWMutex
	keys      map[string]*rsa.PublicKey
	fetchedAt time.Time
	// single ensures a thundering herd of requests triggers one key fetch
	// rather than one per request.
	single sync.Mutex
}

// New returns a Verifier.
func New(cfg Config) (*Verifier, error) {
	if cfg.AuthURL == "" && cfg.JWKSURL == "" && cfg.PublicKey == nil {
		return nil, errors.New("authclient: AuthURL is required " +
			"(or JWKSURL/PublicKey plus Issuer and Audience)")
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}

	// Fill in whatever discovery can tell us, leaving explicit values alone.
	if cfg.AuthURL != "" {
		if err := discover(&cfg); err != nil {
			return nil, err
		}
	}

	if cfg.Issuer == "" || cfg.Audience == "" {
		return nil, errors.New("authclient: Issuer and Audience are required; " +
			"set AuthURL to read them from the auth service, or provide them directly")
	}
	if cfg.JWKSURL == "" && cfg.PublicKey == nil {
		return nil, errors.New("authclient: JWKSURL or PublicKey is required")
	}
	if cfg.CacheTTL <= 0 {
		cfg.CacheTTL = time.Hour
	}
	if cfg.Leeway <= 0 {
		cfg.Leeway = 30 * time.Second
	}
	if cfg.MinRefreshInterval < 0 {
		cfg.MinRefreshInterval = 0
	} else if cfg.MinRefreshInterval == 0 {
		cfg.MinRefreshInterval = time.Minute
	}

	return &Verifier{cfg: cfg, keys: map[string]*rsa.PublicKey{}}, nil
}

// Verify checks a token and returns the caller's identity.
func (v *Verifier) Verify(ctx context.Context, token string) (*Identity, error) {
	parsed, err := jwt.ParseWithClaims(token, &claims{},
		func(t *jwt.Token) (any, error) { return v.keyFor(ctx, t) },
		// Pinned at the parser as well as in keyFor. Either alone rejects a
		// forged algorithm, but relying on the key type to mismatch is an
		// accident of the library rather than a stated rule.
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuer(v.cfg.Issuer),
		jwt.WithAudience(v.cfg.Audience),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(v.cfg.Leeway),
	)
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrExpired
		}
		return nil, fmt.Errorf("%w: %s", ErrInvalid, err)
	}

	c, ok := parsed.Claims.(*claims)
	if !ok || !parsed.Valid {
		return nil, ErrInvalid
	}

	permissions := make(PermissionSet, len(c.Permissions))
	for _, p := range c.Permissions {
		permissions[p] = struct{}{}
	}

	identity := &Identity{
		UserID:       c.Subject,
		Email:        c.Email,
		Roles:        c.Roles,
		Permissions:  permissions,
		TokenVersion: c.TokenVersion,
	}
	if c.ExpiresAt != nil {
		identity.ExpiresAt = c.ExpiresAt.Time
	}
	return identity, nil
}

// keyFor picks the verification key for a token, pinning the signing method.
//
// The method check is the important one. Without it, a token with
// "alg":"none" would be accepted, and under RS256 so would one HMAC-signed
// using the public key as the secret -- and the public key is, by definition,
// something an attacker has.
func (v *Verifier) keyFor(ctx context.Context, token *jwt.Token) (any, error) {
	if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
		return nil, fmt.Errorf("unexpected signing method %q", token.Header["alg"])
	}
	if v.cfg.PublicKey != nil {
		return v.cfg.PublicKey, nil
	}

	kid, _ := token.Header["kid"].(string)
	return v.publicKey(ctx, kid)
}

// publicKey returns the cached key for a kid, refreshing the key set when the
// id is unknown or the cache has expired.
//
// Refreshing on an unknown kid is what makes key rotation work without
// redeploying: a token signed by the new key names an id this process has never
// seen, and that is the signal to go and look again.
func (v *Verifier) publicKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	v.mu.RLock()
	key, found := v.keys[kid]
	fetchedAt := v.fetchedAt
	v.mu.RUnlock()

	if found && time.Since(fetchedAt) < v.cfg.CacheTTL {
		return key, nil
	}

	// Throttle refreshes caused by an unknown id, so a stream of tokens with
	// invented kids cannot be used to hammer the auth service.
	if !found && !fetchedAt.IsZero() && time.Since(fetchedAt) < v.cfg.MinRefreshInterval {
		return nil, fmt.Errorf("%w: no key %q in the key set", ErrInvalid, kid)
	}

	if err := v.refresh(ctx, fetchedAt); err != nil {
		// A stale key still verifies tokens signed before the outage, so a
		// brief JWKS failure does not take authentication down with it.
		if found {
			return key, nil
		}
		return nil, err
	}

	v.mu.RLock()
	key, found = v.keys[kid]
	v.mu.RUnlock()

	if !found {
		return nil, fmt.Errorf("%w: no key %q in the key set", ErrInvalid, kid)
	}
	return key, nil
}

// refresh fetches and caches the key set.
//
// seenAt is the cache timestamp the caller observed before asking. If another
// goroutine has refreshed since then, this one is redundant and returns
// immediately -- which collapses a burst of concurrent misses into one fetch
// without ever skipping a refresh the caller genuinely needed.
func (v *Verifier) refresh(ctx context.Context, seenAt time.Time) error {
	v.single.Lock()
	defer v.single.Unlock()

	v.mu.RLock()
	refreshedByAnother := v.fetchedAt.After(seenAt)
	v.mu.RUnlock()
	if refreshedByAnother {
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.cfg.JWKSURL, nil)
	if err != nil {
		return fmt.Errorf("authclient: build JWKS request: %w", err)
	}

	resp, err := v.cfg.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("authclient: fetch JWKS from %s: %w", v.cfg.JWKSURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("authclient: JWKS endpoint %s returned %d", v.cfg.JWKSURL, resp.StatusCode)
	}

	var document struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&document); err != nil {
		return fmt.Errorf("authclient: decode JWKS: %w", err)
	}
	if len(document.Keys) == 0 {
		return fmt.Errorf("authclient: %s returned no keys", v.cfg.JWKSURL)
	}

	keys := make(map[string]*rsa.PublicKey, len(document.Keys))
	for _, k := range document.Keys {
		if k.Kty != "RSA" {
			continue
		}
		pub, err := parseRSAJWK(k.N, k.E)
		if err != nil {
			return fmt.Errorf("authclient: key %q: %w", k.Kid, err)
		}
		keys[k.Kid] = pub
	}

	v.mu.Lock()
	v.keys = keys
	v.fetchedAt = time.Now()
	v.mu.Unlock()

	return nil
}

// discoveryDocument is the subset of the auth service's discovery document this
// package uses.
type discoveryDocument struct {
	Issuer   string `json:"issuer"`
	JWKSURI  string `json:"jwks_uri"`
	Audience string `json:"audience"`
	// ClaimsSupported is what the auth service says its tokens contain. Used
	// to catch a contract mismatch at startup -- see requiredClaims.
	ClaimsSupported []string `json:"claims_supported"`
}

// requiredClaims are the claims this package reads out of every token.
//
// They are checked against the auth service's advertised claims_supported at
// startup, because this package and the auth service now live in separate
// repositories and nothing makes them change together. Renaming "permissions"
// on the server would otherwise leave every service here with an empty
// permission set -- a 403 for every user, with no error anywhere to explain it.
//
// A mismatch is a startup failure rather than a warning: serving requests with
// a permission set you cannot populate is worse than not starting.
var requiredClaims = []string{"sub", "email", "roles", "permissions"}

// checkClaimContract verifies the auth service advertises everything this
// package needs. It is skipped when the service advertises nothing, so an
// older auth service without claims_supported still works.
func checkClaimContract(advertised []string, source string) error {
	if len(advertised) == 0 {
		return nil
	}

	present := make(map[string]struct{}, len(advertised))
	for _, c := range advertised {
		present[c] = struct{}{}
	}

	var missing []string
	for _, needed := range requiredClaims {
		if _, ok := present[needed]; !ok {
			missing = append(missing, needed)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf(
			"authclient: %s advertises claims %v, which is missing %v that this package reads; "+
				"the auth service and this client are out of step -- upgrade one of them",
			source, advertised, missing)
	}
	return nil
}

// discover reads the auth service's configuration and fills in anything the
// caller did not set explicitly.
//
// It runs once, at startup, and fails loudly. A downstream service that cannot
// reach its auth service has no way to verify anything, so refusing to start is
// more honest than coming up and rejecting every request.
func discover(cfg *Config) error {
	url := strings.TrimRight(cfg.AuthURL, "/") + "/.well-known/openid-configuration"

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("authclient: build discovery request: %w", err)
	}

	resp, err := cfg.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("authclient: fetch %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("authclient: %s returned %d; is AuthURL pointing at the auth service?",
			url, resp.StatusCode)
	}

	var doc discoveryDocument
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return fmt.Errorf("authclient: decode %s: %w", url, err)
	}

	// Explicit configuration always wins: a caller who pins the issuer wants it
	// pinned, not replaced by whatever the endpoint happens to report.
	if cfg.Issuer == "" {
		cfg.Issuer = doc.Issuer
	}
	if cfg.Audience == "" {
		cfg.Audience = doc.Audience
	}
	if cfg.JWKSURL == "" {
		cfg.JWKSURL = doc.JWKSURI
	}

	if err := checkClaimContract(doc.ClaimsSupported, url); err != nil {
		return err
	}

	if cfg.Issuer == "" || cfg.Audience == "" || cfg.JWKSURL == "" {
		return fmt.Errorf("authclient: %s did not report an issuer, audience and jwks_uri", url)
	}
	return nil
}
