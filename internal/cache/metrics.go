package cache

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

func (cache *cache) pushMetrics() {
	os.Stdout.WriteString("pushing metrics\n")
	if cache.config.Pushgateway == nil {
		return
	}

	counter := map[string]IPReport{}
	cache.lock.RLock()
	for ip, rep := range cache.counter {
		// Copy the report to avoid shared memory access while keeping
		// locking to a minimum.
		counter[ip] = *rep
	}
	cache.lock.RUnlock()

	accumMaliciousRequests := map[MaliciousRequestType]uint64{}
	accumBlocks := uint64(0)

	for _, rep := range counter {
		for requestType, cnt := range rep.Requests {
			accumMaliciousRequests[requestType] += cnt
		}

		if rep.Blocked {
			accumBlocks++
		}
	}

	payload := `
# TYPE traefik_block_malicious_ips_blocked_ips gauge
# HELP traefik_block_malicious_ips_blocked_ips Amount of currently blocked IPs.
traefik_block_malicious_ips_blocked_ips ` + strconv.Itoa(int(accumBlocks)) + `
# TYPE traefik_block_malicious_ips_malicious_requests gauge
# HELP traefik_block_malicious_ips_malicious_requests Counts amount of malicious requests.
`

	for requestType, cnt := range accumMaliciousRequests {
		payload += fmt.Sprintf(
			"traefik_block_malicious_ips_malicious_requests{type=\"%s\"} %d\n",
			requestType.toLabelValue(),
			cnt,
		)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*20)
	defer cancel()

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		cache.config.Pushgateway.Address+"/metrics/job/traefik-block-malicious-ips",
		strings.NewReader(payload),
	)

	req.Header.Add("Content-Type", "application/octet-stream")
	if cache.config.Pushgateway.Username != "" {
		req.SetBasicAuth(
			cache.config.Pushgateway.Username,
			cache.config.Pushgateway.Password,
		)
	}

	if err != nil {
		os.Stdout.WriteString(fmt.Sprintf(
			"failed to push metrics to %s: %s\n",
			cache.config.Pushgateway.Address,
			err.Error(),
		))
		return
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		os.Stdout.WriteString(fmt.Sprintf(
			"failed to push metrics to %s: %s\n",
			cache.config.Pushgateway.Address,
			err.Error(),
		))
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		os.Stdout.WriteString("failed to push metrics, reading body failed: " + err.Error() + "\n")
		return
	}

	if resp.StatusCode > 299 {
		os.Stdout.WriteString(fmt.Sprintf(
			"failed to push metrics to %s, unexpected status %d: %s\n",
			cache.config.Pushgateway.Address,
			resp.StatusCode,
			string(body),
		))
	}
}
