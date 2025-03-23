// Package plugindemo a demo plugin.
package traefik_block_malicious_ips

import (
	"context"
	"net/http"

	"github.com/Cubicroots-Playground/traefik-block-malicious-ips/internal/cache"
	"github.com/Cubicroots-Playground/traefik-block-malicious-ips/internal/scanner"
)

// Config the plugin configuration.
type Config struct {
	ResetAfterMinutes                   uint64  `json:"resetAfterMinutes"`
	MinTimeSeconds                      uint64  `json:"minTimeSeconds"`
	MinRequestsCrawler                  uint64  `json:"minRequestsCrawler"`
	MinRequestsAuthEnumeration          uint64  `json:"minRequestsEnumeration"`
	MinRequestsSpam                     uint64  `json:"minRequestsSpam"`
	MinRequestsPerMinuteCrawler         float64 `json:"minRequestsPerMinuteCrawler"`
	MinRequestsPerMinuteAuthEnumeration float64 `json:"minRequestsPerMinuteAuthEnumeration"`
	MinRequestsPerMinuteSpam            float64 `json:"minRequestsPerMinuteSpam"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{}
}

// BlockMaliciousIPsMiddleware a BlockMaliciousIPsMiddleware plugin.
type BlockMaliciousIPsMiddleware struct {
	next   http.Handler
	config *Config

	scanner scanner.Scanner
	cache   cache.Cache
}

// New creates a new plugin.
func New(_ context.Context, next http.Handler, config *Config, _ string) (http.Handler, error) {
	a := &BlockMaliciousIPsMiddleware{
		next:   next,
		config: config,

		scanner: scanner.New(),
	}

	return a, nil
}

func (a *BlockMaliciousIPsMiddleware) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// tbd

	a.next.ServeHTTP(rw, req)
}
