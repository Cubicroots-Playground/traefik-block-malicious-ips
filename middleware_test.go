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

	ctx := context.Background()
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})

	middleware, err := middleware.New(ctx, next, cfg, "geoip-plugin")
	if err != nil {
		t.Fatal(err.Error())
	}

	// Execute.
	recorder := httptest.NewRecorder()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err.Error())
	}

	middleware.ServeHTTP(recorder, req)

	// Assert & clean up.
	if req.Header.Get("Geoip_country_iso") != "DE" {
		t.Errorf("expected DE got '%s'", req.Header.Get("Geoip_country_iso"))
	}
}
