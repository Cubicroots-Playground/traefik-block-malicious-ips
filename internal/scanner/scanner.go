package scanner

import (
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/Cubicroots-Playground/traefik-block-malicious-ips/internal/cache"
)

// Scanner defines an interface to scan incoming requests.
type Scanner interface {
	ScanRequest(*http.Request) cache.MaliciousRequestType
}

type Config struct {
	IncludePrivateIPs bool
}

// New assembles a new scanner.
func New(config *Config) Scanner {
	return &scanner{
		config: config,
	}
}

type scanner struct {
	config *Config
}

func (scanner *scanner) ScanRequest(r *http.Request) cache.MaliciousRequestType {
	remoteAddr := r.Header.Get("X-Real-Ip")

	ip := net.ParseIP(remoteAddr)

	// Could not parse IP.
	if ip == nil {
		os.Stdout.WriteString("could not parse IP '" + remoteAddr + "'\n")
		return cache.MaliciousRequestTypeUnknow
	}

	// Exclude private IP spaces.
	if !scanner.config.IncludePrivateIPs && (ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()) {
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

	crawlers := []string{
		// Google.
		"Googlebot",
		"AdsBot",
		"Feedfetcher",
		"Mediapartners",
		"APIs-Google",
		"InspectionTool",
		"Storebot",
		// Bing.
		"bingbot",
		// Misc.
		"Slurp",
		"WGETbot",
		"LinkedIn",
		// Microsoft.
		"msnbot",
		// Programming.
		"Python",
		"python",
		"libwww",
		"httpunit",
		"Nutch",
		"Go-http-client",
	}
	for _, crawler := range crawlers {
		if strings.Contains(userAgent, crawler) {
			return cache.MaliciousRequestTypeCrawler
		}
	}

	return cache.MaliciousRequestTypeUnknow
}
