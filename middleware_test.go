package traefik_block_malicious_ips_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	middleware "github.com/Cubicroots-Playground/traefik-block-malicious-ips"
)

func TestBlockMaliciousIPsMiddleware(t *testing.T) {
	// Setup.
	cfg := middleware.CreateConfig()
	cfg.IncludePrivateIPs = true

	ctx := context.Background()
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})

	middleware, err := middleware.New(ctx, next, cfg, "blocker")
	if err != nil {
		t.Fatal(err.Error())
	}

	// Execute.
	recorder := httptest.NewRecorder()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err.Error())
	}
	req.Header.Add("X-Real-IP", "127.0.0.1")

	middleware.ServeHTTP(recorder, req)

	// Assert & clean up.
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200 but got %d", recorder.Result().StatusCode)
	}
}

func TestBlockMaliciousIPsMiddlewareWithTriggerAuthEnumeration(t *testing.T) {
	// Setup.
	cfg := middleware.CreateConfig()
	cfg.IncludePrivateIPs = true
	cfg.MinTimeSeconds = 0
	cfg.MinRequestsAuthEnumeration = 10
	cfg.MinRequestsPerMinuteAuthEnumeration = 5

	ctx := context.Background()
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})

	middleware, err := middleware.New(ctx, next, cfg, "blocker")
	if err != nil {
		t.Fatal(err.Error())
	}

	// Execute.
	recorder := httptest.NewRecorder()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err.Error())
	}

	req.Header.Add("Authorization", "super-secret-token")
	req.Header.Add("X-Real-IP", "127.0.0.1")

	// Assert & clean up.
	lastStatusCode := 0
	for range 10 {
		middleware.ServeHTTP(recorder, req)
		lastStatusCode = recorder.Code
	}
	if lastStatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 but got %d", recorder.Result().StatusCode)
	}
}
