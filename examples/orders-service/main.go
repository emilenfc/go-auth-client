// Command orders-service is a small microservice whose routes are protected by
// tokens issued by the auth service.
//
// Two endpoints, which is enough to show both access patterns:
//
//	GET /api/v1/orders/mine   any signed-in user -- no permission needed
//	GET /api/v1/orders        requires the "orders:read" permission
//
// What to notice: there is no user table here, no password handling, and no
// call to the auth service while serving a request. The public keys are fetched
// once and cached; verifying a token is local arithmetic, and the permissions
// ride along inside it.
//
// See examples/README.md to run it.
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/emilenfc/go-auth-client"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("fatal: %v", err)
	}
}

func run() error {
	cfg, err := LoadConfig()
	if err != nil {
		return err
	}

	// One verifier per process.
	//
	// From the base URL it reads the issuer, audience and key location out of
	// the auth service's discovery document, then fetches and caches the public
	// keys -- re-fetching automatically when a token arrives carrying a key id
	// it has not seen, so a key rotation needs no redeploy here.
	verifier, err := authclient.New(authclient.Config{AuthURL: cfg.AuthURL})
	if err != nil {
		return err
	}

	handler := NewHandler(os.Getenv("SEED_OWNER_ID"))

	r := gin.New()
	r.Use(gin.Logger(), gin.Recovery())

	// Public.
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok", "service": "orders"})
	})

	// Authenticate() on the group answers "who is calling?"; the guard on the
	// route answers "may they do this?". Separating them is what lets /mine be
	// authenticated without being permission-gated.
	orders := r.Group("/api/v1/orders", verifier.Authenticate())
	{
		orders.GET("/mine", handler.Mine)
		orders.GET("", authclient.RequirePermission(PermOrdersRead), handler.List)
	}

	server := &http.Server{
		Addr:              cfg.Addr,
		Handler:           r,
		ReadHeaderTimeout: 10 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	serverErr := make(chan error, 1)
	go func() {
		log.Printf("orders-service listening on %s", cfg.Addr)
		log.Printf("verifying tokens issued by %s", cfg.AuthURL)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
	}()

	select {
	case err := <-serverErr:
		return err
	case <-ctx.Done():
		log.Println("shutting down")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return server.Shutdown(shutdownCtx)
}
