// Package plugindemo a demo plugin.
package traefik_block_malicious_ips

import (
	"context"
	"net/http"
	"os"
	"time"

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
	IncludePrivateIPs                   bool    `json:"includePrivateIPs"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		ResetAfterMinutes:                   15,
		MinTimeSeconds:                      5,
		MinRequestsCrawler:                  20,
		MinRequestsAuthEnumeration:          5,
		MinRequestsSpam:                     50,
		MinRequestsPerMinuteCrawler:         0,
		MinRequestsPerMinuteAuthEnumeration: 0,
		MinRequestsPerMinuteSpam:            60,
	}
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

		scanner: scanner.New(&scanner.Config{
			IncludePrivateIPs: config.IncludePrivateIPs,
		}),
		cache: cache.New(&cache.Config{
			ResetAfter: time.Minute * time.Duration(config.ResetAfterMinutes),
			MinRequests: map[cache.MaliciousRequestType]uint64{
				cache.MaliciousRequestTypeAuthEnumeration: config.MinRequestsAuthEnumeration,
				cache.MaliciousRequestTypeCrawler:         config.MinRequestsCrawler,
				cache.MaliciousRequestTypeSpam:            config.MinRequestsSpam,
			},
			MinTime: time.Second * time.Duration(config.MinTimeSeconds),
			MinRequestsPerMinute: map[cache.MaliciousRequestType]float64{
				cache.MaliciousRequestTypeAuthEnumeration: config.MinRequestsPerMinuteAuthEnumeration,
				cache.MaliciousRequestTypeCrawler:         config.MinRequestsPerMinuteCrawler,
				cache.MaliciousRequestTypeSpam:            config.MinRequestsPerMinuteSpam,
			},
		}),
	}

	return a, nil
}

func (a *BlockMaliciousIPsMiddleware) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	scanResult := a.scanner.ScanRequest(req)
	if scanResult != cache.MaliciousRequestTypeUnknow {
		report, err := a.cache.CountRequest(req.Header.Get("X-Real-Ip"), scanResult)
		if err != nil {
			os.Stdout.WriteString("failed to scan request: " + err.Error())
		} else {
			if report.Blocked {
				rw.Header().Add("Request-Blocked", "1")
				rw.WriteHeader(http.StatusNotFound)
				_, _ = rw.Write([]byte("not found"))

				return
			}
		}
	}

	a.next.ServeHTTP(rw, req)
}
