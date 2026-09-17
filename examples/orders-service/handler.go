package main

import (
	"net/http"
	"sort"

	"github.com/gin-gonic/gin"

	"github.com/emilenfc/go-auth-client"
)

// PermOrdersRead is the permission the "list every order" endpoint requires.
//
// It must also exist in the auth service's catalogue -- that is what grants it.
// Add it to internal/domain/permissions_catalog.go there:
//
//	PermOrdersRead = define("orders:read", "List and view orders")
//
// Give each service its own resource prefix so names cannot collide.
const PermOrdersRead = "orders:read"

// Order is this service's own data. OwnerID holds the auth service's user id,
// the only identifier the two services share.
type Order struct {
	ID      string `json:"id"`
	OwnerID string `json:"owner_id"`
	Item    string `json:"item"`
}

// Handler serves the order endpoints. The store stands in for a database.
type Handler struct {
	orders []Order
}

// NewHandler returns a Handler seeded with orders for two different owners, so
// that "mine" and "all" visibly differ.
func NewHandler(seedOwnerID string) *Handler {
	return &Handler{orders: []Order{
		{ID: "ord-1", OwnerID: seedOwnerID, Item: "Keyboard"},
		{ID: "ord-2", OwnerID: seedOwnerID, Item: "Monitor"},
		{ID: "ord-3", OwnerID: "someone-else", Item: "Desk"},
	}}
}

// Mine returns the caller's own orders.
//
// Authenticated but deliberately NOT permission-gated: any signed-in user may
// see their own orders. The filtering uses the user id from the token, which is
// why no permission is needed -- the caller cannot ask for anyone else's.
func (h *Handler) Mine(c *gin.Context) {
	identity := authclient.MustIdentity(c)

	mine := []Order{}
	for _, o := range h.orders {
		if o.OwnerID == identity.UserID {
			mine = append(mine, o)
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"caller": gin.H{
			"user_id":     identity.UserID,
			"email":       identity.Email,
			"roles":       identity.Roles,
			"permissions": sortedNames(identity.Permissions),
		},
		"orders": mine,
	})
}

// List returns every order, for callers holding orders:read.
//
// The permission check happens in the route table, not here -- if this handler
// runs at all, the caller was allowed.
func (h *Handler) List(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"orders": h.orders})
}

func sortedNames(set authclient.PermissionSet) []string {
	names := make([]string, 0, len(set))
	for n := range set {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
