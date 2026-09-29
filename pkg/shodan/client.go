package shodan

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

const BaseURL = "https://api.shodan.io"

type Target struct {
	IP       string
	Hostname string
	Port     int
}

type HostResponse struct {
	IPStr     string   `json:"ip_str"`
	Ports     []int    `json:"ports"`
	Hostnames []string `json:"hostnames"`
	Org       string   `json:"org"`
	ISP       string   `json:"isp"`
}

type SearchResponse struct {
	Matches []struct {
		IPStr     string   `json:"ip_str"`
		Hostnames []string `json:"hostnames"`
		Ports     []int    `json:"ports"`
	} `json:"matches"`
}

var httpClient = &http.Client{Timeout: 30 * time.Second}

func GetHost(apiKey, ip string) (*HostResponse, error) {
	u := fmt.Sprintf("%s/shodan/host/%s?key=%s", BaseURL, ip, apiKey)
	resp, err := httpClient.Get(u)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		return nil, fmt.Errorf("no Shodan data for this IP")
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("shodan API error: %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	var host HostResponse
	if err := json.Unmarshal(body, &host); err != nil {
		return nil, err
	}
	return &host, nil
}

func SearchHosts(apiKey, query string, pages int, delaySeconds int) ([]Target, error) {
	var all []Target
	seen := make(map[string]bool)
	encoded := url.QueryEscape(query)

	for page := 1; page <= pages; page++ {
		apiURL := fmt.Sprintf(
			"%s/shodan/host/search?key=%s&query=%s&minify=true&page=%d",
			BaseURL, apiKey, encoded, page,
		)
		resp, err := httpClient.Get(apiURL)
		if err != nil {
			fmt.Printf("[-] Page %d failed: %v\n", page, err)
			break
		}
		if resp.StatusCode == 401 {
			resp.Body.Close()
			return all, fmt.Errorf("invalid Shodan API key")
		}
		if resp.StatusCode != 200 {
			resp.Body.Close()
			fmt.Printf("[-] Page %d returned %d\n", page, resp.StatusCode)
			break
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		var sr SearchResponse
		if err := json.Unmarshal(body, &sr); err != nil {
			fmt.Printf("[-] Page %d parse failed\n", page)
			break
		}
		if len(sr.Matches) == 0 {
			fmt.Printf("[*] Page %d: 0 results. Done.\n", page)
			break
		}

		added := 0
		for _, m := range sr.Matches {
			if seen[m.IPStr] {
				continue
			}
			seen[m.IPStr] = true
			t := Target{IP: m.IPStr}
			if len(m.Hostnames) > 0 {
				t.Hostname = m.Hostnames[0]
			}
			if len(m.Ports) > 0 {
				t.Port = m.Ports[0]
			}
			all = append(all, t)
			added++
		}
		fmt.Printf("[*] Page %d: +%d new (total %d)\n", page, added, len(all))

		if page < pages && delaySeconds > 0 {
			time.Sleep(time.Duration(delaySeconds) * time.Second)
		}
	}
	return all, nil
}
