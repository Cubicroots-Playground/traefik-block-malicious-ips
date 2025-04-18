package cache

import (
	"os"
	"sync"
	"time"
)

// Cache describes an interface to cache malicious requests.
type Cache interface {
	CountRequest(string, MaliciousRequestType) (IPReport, error)
}

type Config struct {
	ResetAfter time.Duration

	// An IP needs to make at least this amount of requests to be blocked.
	MinRequests map[MaliciousRequestType]uint64
	// An IP needs to make requests for at least this amount of time to be blocked.
	MinTime time.Duration
	// An IP needs to exceed at least this amount of requests per minutes to be blocked.
	MinRequestsPerMinute map[MaliciousRequestType]float64

	// Configure metrics being send to a prometheus push gateway.
	Pushgateway *PrometheusPushGatewayConfig
}

type PrometheusPushGatewayConfig struct {
	Address string

	// Username and password for basic auth.
	Username string
	Password string
}

// New assembles a new cache.
func New(cfg *Config) Cache {
	service := &cache{
		lock:    sync.RWMutex{},
		counter: map[string]*IPReport{},
		config:  cfg,
	}

	go service.runJobs()

	return service
}

type cache struct {
	lock    sync.RWMutex
	counter map[string]*IPReport

	config *Config
}

// MaliciousRequestType specifies the type of malicious request.
type MaliciousRequestType int

func (requestType MaliciousRequestType) toLabelValue() string {
	switch requestType {
	case MaliciousRequestTypeAuthEnumeration:
		return "auth_enumeration"
	case MaliciousRequestTypeSpam:
		return "spam"
	case MaliciousRequestTypeCrawler:
		return "crawler"
	default:
		return "unknown"
	}
}

// List of available malicious request types.
const (
	MaliciousRequestTypeUnknow = iota
	MaliciousRequestTypeAuthEnumeration
	MaliciousRequestTypeSpam
	MaliciousRequestTypeCrawler
)

// IPReports holds information about an IP.
type IPReport struct {
	Requests  map[MaliciousRequestType]uint64
	Blocked   bool
	FirstSeen time.Time
	LastSeen  time.Time
}

func (cache *cache) CountRequest(
	sourceIP string,
	requestType MaliciousRequestType,
) (IPReport, error) {
	cache.lock.Lock()
	defer cache.lock.Unlock()

	if rep, ok := cache.counter[sourceIP]; ok {
		rep.Requests[requestType]++
		rep.LastSeen = time.Now()
		rep.Blocked = cache.shouldBlock(rep)

		return *rep, nil
	}

	rep := IPReport{
		Requests:  map[MaliciousRequestType]uint64{requestType: 1},
		FirstSeen: time.Now(),
		LastSeen:  time.Now(),
	}
	rep.Blocked = cache.shouldBlock(&rep)
	cache.counter[sourceIP] = &rep

	return rep, nil
}

func (cache *cache) shouldBlock(report *IPReport) bool {
	// Check if entry should be reset.
	if report.Blocked && time.Since(report.LastSeen) > cache.config.ResetAfter {
		return false
	}

	// Check if minimum time requirement is met.
	if report.LastSeen.Sub(report.FirstSeen) < cache.config.MinTime {
		return false
	}

	// Check if minimum request criteria is met.
	block := false
	for requestType, min := range cache.config.MinRequests {
		if report.Requests[requestType] >= min {
			block = true
			break
		}
	}

	if !block {
		return false
	}

	// Check if min request rate criteria is met.
	block = false
	timeRange := report.LastSeen.Sub(report.FirstSeen).Minutes()
	for requestType, min := range cache.config.MinRequestsPerMinute {
		rate := float64(report.Requests[requestType]) / timeRange
		if rate >= min {
			block = true
			break
		}
	}

	return block
}

func (cache *cache) runJobs() {
	cleanupTicker := time.NewTicker(time.Minute)
	metricsTicker := time.NewTicker(time.Minute + time.Millisecond*299)
	for {
		select {
		case <-metricsTicker.C:
			cache.pushMetrics()
		case <-cleanupTicker.C:
			cache.cleanup()
		}
	}
}

func (cache *cache) cleanup() {
	cache.lock.Lock()
	defer cache.lock.Unlock()

	for ip, report := range cache.counter {
		if time.Since(report.LastSeen) > cache.config.ResetAfter {
			os.Stdout.WriteString("Deleting cache entry for " + ip + "\n")
			delete(cache.counter, ip)
		}
	}
}
