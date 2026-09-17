package authclient

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// ContextKeyIdentity is where the authenticated caller is stored on the gin
// context.
const ContextKeyIdentity = "authclient.identity"

// DeniedMessage matches the auth service's own wording, so a client sees the
// same sentence whichever service refused it. It names no permission: a caller
// cannot act on that detail anyway, and publishing it maps out the permission
// model for anyone probing endpoints.
const DeniedMessage = "you don't have permission to access this endpoint"

// ErrorResponse is the body returned on a rejection. It matches the auth
// service's envelope so a client can parse failures the same way everywhere.
type ErrorResponse struct {
	Success bool `json:"success"`
	Status  int  `json:"status"`
	Error   struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func abort(c *gin.Context, status int, code, message string) {
	var body ErrorResponse
	body.Success = false
	body.Status = status
	body.Error.Code = code
	body.Error.Message = message
	c.AbortWithStatusJSON(status, body)
}

// Authenticate validates the bearer token and attaches the caller's identity.
//
// Put it on the router group; put RequirePermission on the individual routes.
// Keeping the two separate is what lets a route be authenticated but
// unauthorised -- "show me my own profile" needs to know who you are and
// nothing more.
func (v *Verifier) Authenticate() gin.HandlerFunc {
	return func(c *gin.Context) {
		token, err := bearerToken(c)
		if err != nil {
			abort(c, http.StatusUnauthorized, "unauthorized", err.Error())
			return
		}

		identity, err := v.Verify(c.Request.Context(), token)
		if err != nil {
			switch {
			case errors.Is(err, ErrExpired):
				abort(c, http.StatusUnauthorized, "token_expired",
					"your access token has expired; refresh it and try again")
			default:
				abort(c, http.StatusUnauthorized, "token_invalid",
					"your access token is not valid")
			}
			return
		}

		c.Set(ContextKeyIdentity, identity)
		c.Next()
	}
}

// OptionalAuthenticate attaches an identity when a valid token is present and
// otherwise continues anonymously, for endpoints that serve both.
func (v *Verifier) OptionalAuthenticate() gin.HandlerFunc {
	return func(c *gin.Context) {
		if token, err := bearerToken(c); err == nil {
			if identity, err := v.Verify(c.Request.Context(), token); err == nil {
				c.Set(ContextKeyIdentity, identity)
			}
		}
		c.Next()
	}
}

// RequirePermission gates a route on a permission.
//
//	orders.GET("", authclient.RequirePermission("orders:read"), h.List)
//
// The check is a map lookup against the verified claims -- no database, no call
// to the auth service.
func RequirePermission(permission string) gin.HandlerFunc {
	return func(c *gin.Context) {
		identity := MustIdentity(c)
		if !identity.Can(permission) {
			abort(c, http.StatusForbidden, "forbidden", DeniedMessage)
			return
		}
		c.Next()
	}
}

// RequireAnyPermission allows a caller holding at least one of the permissions.
func RequireAnyPermission(permissions ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !MustIdentity(c).Permissions.HasAny(permissions...) {
			abort(c, http.StatusForbidden, "forbidden", DeniedMessage)
			return
		}
		c.Next()
	}
}

// RequireAllPermissions demands every permission.
func RequireAllPermissions(permissions ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !MustIdentity(c).Permissions.HasAll(permissions...) {
			abort(c, http.StatusForbidden, "forbidden", DeniedMessage)
			return
		}
		c.Next()
	}
}

// RequireSelfOrPermission allows a caller acting on their own record, or any
// caller holding the permission. The id is read from the named path parameter
// and compared against the token's subject.
func RequireSelfOrPermission(param, permission string) gin.HandlerFunc {
	return func(c *gin.Context) {
		identity := MustIdentity(c)
		if c.Param(param) == identity.UserID || identity.Can(permission) {
			c.Next()
			return
		}
		abort(c, http.StatusForbidden, "forbidden", DeniedMessage)
	}
}

// IdentityFrom returns the authenticated caller, if there is one.
func IdentityFrom(c *gin.Context) (*Identity, bool) {
	value, exists := c.Get(ContextKeyIdentity)
	if !exists {
		return nil, false
	}
	identity, ok := value.(*Identity)
	return identity, ok
}

// MustIdentity returns the authenticated caller, panicking if there is none.
//
// A panic is right: it means a route behind RequirePermission was reached
// without Authenticate in front of it, which is a wiring bug. Treating the
// request as anonymous instead would hide a hole in the route table.
func MustIdentity(c *gin.Context) *Identity {
	identity, ok := IdentityFrom(c)
	if !ok {
		panic("authclient: RequirePermission used on a route that is not behind Authenticate()")
	}
	return identity
}

// bearerToken extracts the token from the Authorization header.
func bearerToken(c *gin.Context) (string, error) {
	header := c.GetHeader("Authorization")
	if header == "" {
		return "", errors.New("this endpoint requires an access token; send it as `Authorization: Bearer <token>`")
	}

	scheme, token, found := strings.Cut(header, " ")
	if !found || !strings.EqualFold(scheme, "Bearer") || strings.TrimSpace(token) == "" {
		return "", errors.New("the Authorization header must be in the form `Bearer <token>`")
	}
	return strings.TrimSpace(token), nil
}
