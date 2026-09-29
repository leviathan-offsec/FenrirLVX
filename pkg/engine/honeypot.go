package engine

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

type HoneypotCheck struct {
	IsHoneypot bool
	Reason     string
}

var trapServers = []string{
	"glastopf", "dionaea", "tarpit", "honeypot",
	"kippo", "cowrie", "heralding", "nepenthes",
}

func DetectHoneypot(resp *http.Response, body []byte, elapsed time.Duration, pluginCount int) HoneypotCheck {
	if elapsed < 60*time.Millisecond && pluginCount > 5 {
		return HoneypotCheck{true, "sub-60ms response with many plugins"}
	}
	if pluginCount >= 30 {
		return HoneypotCheck{true, fmt.Sprintf("%d plugins — likely canary", pluginCount)}
	}
	if resp != nil {
		server := strings.ToLower(resp.Header.Get("Server"))
		for _, sig := range trapServers {
			if strings.Contains(server, sig) {
				return HoneypotCheck{true, "server: " + sig}
			}
		}
		for _, h := range []string{"X-Honeypot", "X-Canary", "X-Trap"} {
			if resp.Header.Get(h) != "" {
				return HoneypotCheck{true, "header: " + h}
			}
		}
		if strings.Contains(server, "wordpress") {
			s := string(body)
			if !strings.Contains(s, "wp-content") &&
				!strings.Contains(s, "wp-includes") &&
				!strings.Contains(s, "wp-json") {
				return HoneypotCheck{true, "claims WordPress but body has no WP markers"}
			}
		}
	}
	return HoneypotCheck{false, ""}
}
