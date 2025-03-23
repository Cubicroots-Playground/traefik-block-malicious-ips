package traefik_block_malicious_ips_test

import (
	"net/http/httptest"
	"testing"
)

var geoIPAPIMock *httptest.Server

func TestMain(m *testing.M) {
	m.Run()
}
