package engine

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

var (
	wpOrgCache   = make(map[string]string)
	wpOrgCacheMu sync.RWMutex
	wpOrgClient  = &http.Client{Timeout: 5 * time.Second}
)

type wpOrgResponse struct {
	Version string `json:"version"`
}

func GetLatestWordPressOrgVersion(slug string) string {
	wpOrgCacheMu.RLock()
	if v, ok := wpOrgCache[slug]; ok {
		wpOrgCacheMu.RUnlock()
		return v
	}
	wpOrgCacheMu.RUnlock()

	apiURL := fmt.Sprintf(
		"https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&request[slug]=%s",
		slug,
	)
	resp, err := wpOrgClient.Get(apiURL)
	if err != nil || resp == nil {
		wpOrgCacheMu.Lock()
		wpOrgCache[slug] = ""
		wpOrgCacheMu.Unlock()
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		wpOrgCacheMu.Lock()
		wpOrgCache[slug] = ""
		wpOrgCacheMu.Unlock()
		return ""
	}

	var r wpOrgResponse
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return ""
	}

	wpOrgCacheMu.Lock()
	wpOrgCache[slug] = r.Version
	wpOrgCacheMu.Unlock()
	return r.Version
}

func SanityCheckVersion(slug, detected string) bool {
	if detected == "unknown" || detected == "" {
		return false
	}
	latest := GetLatestWordPressOrgVersion(slug)
	if latest == "" {
		return true
	}
	d := parseSemver(detected)
	l := parseSemver(latest)
	if d[0] > l[0]+1 {
		return false
	}
	return true
}
