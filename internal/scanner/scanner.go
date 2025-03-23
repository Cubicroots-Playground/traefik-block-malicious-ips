package scanner

import (
	"context"
	"net"
	"net/http"
	"os"

	"github.com/Cubicroots-Playground/traefik-block-malicious-ips/internal/cache"
	agents "github.com/monperrus/crawler-user-agents"
)

// Scanner defines an interface to scan incoming requests.
type Scanner interface {
	ScanRequest(context.Context, *http.Request) cache.MaliciousRequestType
}

// New assembles a new scanner.
func New() Scanner {
	return &scanner{}
}

type scanner struct{}

func (scanner *scanner) ScanRequest(_ context.Context, r *http.Request) cache.MaliciousRequestType {
	remoteAddr := r.Header.Get("X-Real-Ip")

	ip := net.ParseIP(remoteAddr)

	// Could not parse IP.
	if ip == nil {
		os.Stdout.WriteString("could not parse IP " + remoteAddr)
		return cache.MaliciousRequestTypeUnknow
	}

	// Exclude private IP spaces.
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return cache.MaliciousRequestTypeUnknow
	}

	// Scan for authentication enumerations.
	if res := scanner.detectAuthEnumeration(r); res != cache.MaliciousRequestTypeUnknow {
		return res
	}

	// Scan for crawlers.
	if res := scanner.detectCrawler(r); res != cache.MaliciousRequestTypeUnknow {
		return res
	}

	// Default to spam.
	return cache.MaliciousRequestTypeSpam
}

func (scanner *scanner) detectAuthEnumeration(r *http.Request) cache.MaliciousRequestType {
	_, _, ok := r.BasicAuth()
	if ok {
		return cache.MaliciousRequestTypeAuthEnumeration
	}

	authHeaders := []string{
		"Authorization",
		"Token",
		"Authenticate",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"Login",
		"Set-Login",
		"WWW-Authenticate",
	}
	for _, header := range authHeaders {
		value := r.Header.Get(header)
		if value != "" {
			return cache.MaliciousRequestTypeAuthEnumeration
		}
	}

	authParams := []string{
		"login",
		"token",
		"auth",
		"authorization",
		"authentication",
		"password",
	}
	for _, param := range authParams {
		value := r.URL.Query().Get(param)
		if value != "" {
			return cache.MaliciousRequestTypeAuthEnumeration
		}
	}

	return cache.MaliciousRequestTypeUnknow
}

func (scanner *scanner) detectCrawler(r *http.Request) cache.MaliciousRequestType {
	// Check if user agent is known.
	userAgent := r.UserAgent()
	if userAgent == "" {
		return cache.MaliciousRequestTypeUnknow
	}

	if agents.IsCrawler(userAgent) {
		return cache.MaliciousRequestTypeCrawler
	}

	return cache.MaliciousRequestTypeUnknow
}
