# go-auth-client

Verify access tokens issued by
[`golang-main-user-service`](https://github.com/emilenfc/golang-main-user-service)
from any Go service.

Authorising a request costs no network call: the token carries the caller's
roles and permissions, signed, so checking one is local arithmetic.

```go
verifier, err := authclient.New(authclient.Config{
    AuthURL: "http://auth.internal:8080",
})

orders := r.Group("/orders", verifier.Authenticate())
orders.GET("", authclient.RequirePermission("orders:read"), h.List)
```

## Install

```bash
go get github.com/emilenfc/go-auth-client
```

## Configure

One setting. The issuer, audience and public-key location are read from
`<AuthURL>/.well-known/openid-configuration` at startup:

```go
authclient.New(authclient.Config{AuthURL: os.Getenv("AUTH_URL")})
```

Set any of them explicitly to override discovery:

```go
authclient.New(authclient.Config{
    JWKSURL:  "http://auth:8080/.well-known/jwks.json",
    Issuer:   "go-auth-starter",
    Audience: "go-auth-starter-api",
})
```

A wrong `AuthURL` fails at startup rather than on the first request — a service
that cannot reach its auth service cannot verify anything, so refusing to start
is better than serving 401s.

## Guards

```go
verifier.Authenticate()                    // require a valid token
verifier.OptionalAuthenticate()            // attach identity if present, else continue

authclient.RequirePermission("x:read")
authclient.RequireAnyPermission("a", "b")
authclient.RequireAllPermissions("a", "b")
authclient.RequireSelfOrPermission("id", "users:read")  // own record, or permission

authclient.MustIdentity(c)                 // the caller; panics if not behind Authenticate
authclient.IdentityFrom(c)                 // (identity, ok)
```

`Authenticate()` goes on the group and answers *who is calling*; the permission
guards go on routes and answer *may they do this*. Keeping them separate is what
lets a route be authenticated without being permission-gated — "list my own
orders" needs to know who you are and nothing more.

`Identity` carries `UserID` (the token's `sub`), `Email`, `Roles`,
`Permissions`, `TokenVersion` and `ExpiresAt`.

## Tests

```bash
make test     # run the suite
make test-v   # name each test as it runs
make race     # under the race detector — do this before pushing
make check    # format, vet, and race in one pass
make help     # every target
```

They cover what must never silently regress: `alg=none`, a token signed with a
foreign key, the RS256→HS256 confusion attack, wrong issuer, wrong audience,
expiry, unknown key id, the claim contract, and the gin guards. No database and
no running auth service — the auth server is `httptest` and keys are generated
in-process.

## Example

[`examples/orders-service`](examples/orders-service) — a service with a public
route, an authenticated-only route and a permission-gated one.

```bash
make example                    # or:
AUTH_URL=http://localhost:8080 go run ./examples/orders-service
```

## Behaviour worth knowing

**Keys are cached** for an hour, and re-fetched early when a token arrives with
an unknown key id — so rotating the signing key needs no redeploy. If the key
set is briefly unreachable, cached keys keep working.

**Issuer and audience are checked on every token.** A valid signature proves
only that this key signed it, not who minted it or who it was for.

**Signing methods are pinned.** A token with `alg: none`, or one HMAC-signed
using the public key as the secret, is rejected.

**Permission changes take effect on the next token** — 15 minutes by default.
A user granted a new role keeps getting 403 until their token refreshes. That is
the trade which removes a database lookup from every request.

**Revocation is not instant**, for the same reason: this package never calls the
auth service, so it does not see a revoked session until the token expires.

**Claims are checked against the auth service at startup.** This package reads
`sub`, `email`, `roles` and `permissions`. If the discovery document advertises
a `claims_supported` list missing any of them, `New` fails — otherwise a rename
on the server would silently hand every caller an empty permission set.

**User tokens only.** Machine-to-machine calls need client-credentials tokens,
which the auth service does not issue.
