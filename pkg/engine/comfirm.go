package engine

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

// EnrichWithChangelog checks plugin directories for changelog/readme files
// to confirm active version evidence.
func EnrichWithChangelog(f *Finding, baseURL string) int {
	if f == nil || len(f.Plugins) == 0 {
		return 0
	}
	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	hits := 0
	base := strings.TrimRight(baseURL, "/")

	for slug := range f.Plugins {
		candidates := []string{
			fmt.Sprintf("%s/wp-content/plugins/%s/readme.txt", base, slug),
			fmt.Sprintf("%s/wp-content/plugins/%s/changelog.txt", base, slug),
		}
		for _, u := range candidates {
			resp, err := client.Get(u)
			if err == nil && resp != nil {
				if resp.StatusCode == http.StatusOK {
					hits++
					_ = resp.Body.Close()
					break
				}
				_ = resp.Body.Close()
			}
		}
	}
	return hits
}

// ConfidenceScore computes a 0-100 score based on detected version evidence,
// changelog validation, and honeypot risk.
func ConfidenceScore(f *Finding, changelogHits int) int {
	if f == nil || f.Honeypot || f.VulnCount() == 0 {
		return 0
	}

	score := 40 // base signal for detected plugin vulnerability match

	// If plugin versions are confirmed (not empty/generic)
	knownVersions := 0
	for _, v := range f.Plugins {
		if v != "" && v != "unknown" {
			knownVersions++
		}
	}
	if knownVersions > 0 {
		score += 30
	}

	// Changelog presence adds high confidence
	if changelogHits > 0 {
		score += 25
	}

	// Status 200 adds validity
	if f.StatusCode == http.StatusOK {
		score += 5
	}

	if score > 100 {
		score = 100
	}
	return score
}
