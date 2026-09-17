package authclient

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func init() { gin.SetMode(gin.TestMode) }

// routerFor builds a router with the guards a real service would use.
func routerFor(t *testing.T, auth *fakeAuth) *gin.Engine {
	t.Helper()

	v := auth.verifier(t)
	r := gin.New()

	r.GET("/public", func(c *gin.Context) { c.Status(http.StatusOK) })

	protected := r.Group("/api", v.Authenticate())
	{
		protected.GET("/whoami", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"user_id": MustIdentity(c).UserID})
		})
		protected.GET("/read", RequirePermission("orders:read"),
			func(c *gin.Context) { c.Status(http.StatusOK) })
		protected.GET("/delete", RequirePermission("orders:delete"),
			func(c *gin.Context) { c.Status(http.StatusOK) })
		protected.GET("/any", RequireAnyPermission("nope:x", "orders:read"),
			func(c *gin.Context) { c.Status(http.StatusOK) })
		protected.GET("/all", RequireAllPermissions("orders:read", "orders:delete"),
			func(c *gin.Context) { c.Status(http.StatusOK) })
		protected.GET("/self/:id", RequireSelfOrPermission("id", "users:manage"),
			func(c *gin.Context) { c.Status(http.StatusOK) })
	}
	return r
}

func get(t *testing.T, r *gin.Engine, path, token string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

func TestAuthenticateGatesProtectedRoutes(t *testing.T) {
	auth := newFakeAuth(t)
	r := routerFor(t, auth)
	token := auth.signRS256(t, auth.claims())

	tests := []struct {
		name  string
		path  string
		token string
		want  int
	}{
		{"public route needs nothing", "/public", "", http.StatusOK},
		{"protected route without a token", "/api/whoami", "", http.StatusUnauthorized},
		{"protected route with a token", "/api/whoami", token, http.StatusOK},
		{"granted permission", "/api/read", token, http.StatusOK},
		{"ungranted permission", "/api/delete", token, http.StatusForbidden},
		{"any-of, one held", "/api/any", token, http.StatusOK},
		{"all-of, one missing", "/api/all", token, http.StatusForbidden},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := get(t, r, tt.path, tt.token).Code; got != tt.want {
				t.Errorf("%s = %d, want %d", tt.path, got, tt.want)
			}
		})
	}
}

// TestRequireSelfOrPermission: the caller reaches their own record without any
// permission, and anyone else's only with one.
func TestRequireSelfOrPermission(t *testing.T) {
	auth := newFakeAuth(t)
	r := routerFor(t, auth)
	token := auth.signRS256(t, auth.claims())

	own := "/self/11111111-2222-3333-4444-555555555555" // the token's sub
	if got := get(t, r, "/api"+own, token).Code; got != http.StatusOK {
		t.Errorf("own record = %d, want 200", got)
	}
	if got := get(t, r, "/api/self/99999999-9999-9999-9999-999999999999", token).Code; got != http.StatusForbidden {
		t.Errorf("someone else's record = %d, want 403", got)
	}
}

// TestMalformedAuthorizationHeaders are rejected without reaching a handler.
func TestMalformedAuthorizationHeaders(t *testing.T) {
	auth := newFakeAuth(t)
	r := routerFor(t, auth)

	for _, header := range []string{"", "Bearer", "Bearer ", "Basic abc", auth.signRS256(t, auth.claims())} {
		req := httptest.NewRequest(http.MethodGet, "/api/whoami", nil)
		if header != "" {
			req.Header.Set("Authorization", header)
		}
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("Authorization: %q gave %d, want 401", header, rec.Code)
		}
	}
}

// TestDenialBodyShape: failures carry the same envelope the auth service uses,
// so a client parses errors the same way whichever service produced them.
func TestDenialBodyShape(t *testing.T) {
	auth := newFakeAuth(t)
	r := routerFor(t, auth)

	rec := get(t, r, "/api/delete", auth.signRS256(t, auth.claims()))

	var body struct {
		Success bool `json:"success"`
		Status  int  `json:"status"`
		Error   struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response is not the expected envelope: %v\n%s", err, rec.Body)
	}

	if body.Success || body.Status != http.StatusForbidden {
		t.Errorf("envelope = %+v", body)
	}
	if body.Error.Code != "forbidden" {
		t.Errorf("code = %q, want forbidden", body.Error.Code)
	}
	// The message must not name the permission: a caller cannot act on it, and
	// publishing it maps out the permission model for anyone probing.
	if body.Error.Message != DeniedMessage {
		t.Errorf("message = %q, want the generic denial", body.Error.Message)
	}
	if contains(body.Error.Message, "orders:delete") {
		t.Error("the denial names the missing permission")
	}
}

// TestOptionalAuthenticate serves both signed-in and anonymous callers.
func TestOptionalAuthenticate(t *testing.T) {
	auth := newFakeAuth(t)
	v := auth.verifier(t)

	r := gin.New()
	r.GET("/maybe", v.OptionalAuthenticate(), func(c *gin.Context) {
		if identity, ok := IdentityFrom(c); ok {
			c.JSON(http.StatusOK, gin.H{"who": identity.Email})
			return
		}
		c.JSON(http.StatusOK, gin.H{"who": "anonymous"})
	})

	if body := get(t, r, "/maybe", "").Body.String(); !contains(body, "anonymous") {
		t.Errorf("no token should be anonymous, got %s", body)
	}
	if body := get(t, r, "/maybe", auth.signRS256(t, auth.claims())).Body.String(); !contains(body, "ada@example.com") {
		t.Errorf("a valid token should be identified, got %s", body)
	}
	// An invalid token is ignored rather than rejected: the route does not
	// require authentication, so failing it would be surprising.
	if body := get(t, r, "/maybe", "garbage").Body.String(); !contains(body, "anonymous") {
		t.Errorf("an invalid token should fall through to anonymous, got %s", body)
	}
}

// TestMustIdentityPanicsOutsideAuthenticate catches a wiring mistake -- a
// permission guard on a route with no Authenticate in front of it -- loudly,
// rather than treating the request as anonymous and hiding the hole.
func TestMustIdentityPanicsOutsideAuthenticate(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("MustIdentity did not panic on an unauthenticated route")
		}
	}()

	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	MustIdentity(c)
}
