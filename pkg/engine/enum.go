package engine

import (
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strings"
)

type WPPlugin struct {
	Plugin  string `json:"plugin"`
	Status  string `json:"status"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

func GetPluginVersionFromReadme(baseURL, slug string) string {
	base := strings.TrimSuffix(baseURL, "/")
	readmeURL := normalizeURL(base + "/wp-content/plugins/" + slug + "/readme.txt")

	req, err := http.NewRequest("GET", readmeURL, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")

	resp, err := httpClient.Do(req)
	if err != nil || resp == nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return ""
	}

	body, _ := io.ReadAll(resp.Body)
	re := regexp.MustCompile(`(?i)Stable tag:\s*([0-9.]+)`)
	m := re.FindStringSubmatch(string(body))
	if len(m) > 1 {
		return m[1]
	}
	return ""
}

func Enumerate(url string, body []byte) (map[string]string, []string) {
	plugins := make(map[string]string)
	themes := []string{}

	url = normalizeURL(url)

	// 1. REST API (highest trust)
	apiURL := strings.TrimSuffix(url, "/") + "/wp-json/wp/v2/plugins"
	resp, err := httpClient.Get(apiURL)
	if err == nil && resp != nil && resp.StatusCode == 200 {
		defer resp.Body.Close()
		apiBody, _ := io.ReadAll(resp.Body)
		var apiPlugins []WPPlugin
		if err := json.Unmarshal(apiBody, &apiPlugins); err == nil {
			for _, p := range apiPlugins {
				plugins[p.Plugin] = p.Version
			}
		}
	}

	// 2. Asset query strings with sanity filter
	versionRegex := regexp.MustCompile(`/wp-content/plugins/([a-zA-Z0-9-]+)/[^"']*?[?&]ver=([0-9][0-9.]*)`)
	for _, m := range versionRegex.FindAllStringSubmatch(string(body), -1) {
		slug, ver := m[1], m[2]
		if !looksLikeVersion(ver) {
			continue
		}
		if _, exists := plugins[slug]; !exists {
			plugins[slug] = ver
		}
	}

	// 3. readme.txt for remaining unknowns
	pluginRegex := regexp.MustCompile(`/wp-content/plugins/([a-zA-Z0-9-]+)/`)
	for _, p := range pluginRegex.FindAllStringSubmatch(string(body), -1) {
		slug := p[1]
		if _, exists := plugins[slug]; !exists {
			if v := GetPluginVersionFromReadme(url, slug); v != "" && looksLikeVersion(v) {
				plugins[slug] = v
			} else {
				plugins[slug] = "unknown"
			}
		}
	}

	// 4. Sanity check against wordpress.org
	for slug, ver := range plugins {
		if ver == "unknown" || ver == "" {
			continue
		}
		if !SanityCheckVersion(slug, ver) {
			plugins[slug] = "unknown"
		}
	}

	// 5. Themes
	themeRegex := regexp.MustCompile(`/wp-content/themes/([a-zA-Z0-9-]+)/`)
	seen := make(map[string]bool)
	for _, t := range themeRegex.FindAllStringSubmatch(string(body), -1) {
		if !seen[t[1]] {
			seen[t[1]] = true
			themes = append(themes, t[1])
		}
	}

	return plugins, themes
}
