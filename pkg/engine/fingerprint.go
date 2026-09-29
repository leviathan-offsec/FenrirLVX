package engine

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

// normalizeURL ensures scheme and brackets IPv6 hosts.
func normalizeURL(raw string) string {
	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		raw = "https://" + raw
	}
	idx := strings.Index(raw, "://")
	if idx == -1 {
		return raw
	}
	scheme := raw[:idx+3]
	rest := raw[idx+3:]
	slash := strings.Index(rest, "/")
	host := rest
	path := ""
	if slash != -1 {
		host = rest[:slash]
		path = rest[slash:]
	}
	hostOnly := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		hostOnly = h
	}
	if ip := net.ParseIP(strings.Trim(hostOnly, "[]")); ip != nil && ip.To4() == nil {
		if !strings.HasPrefix(host, "[") {
			host = "[" + hostOnly + "]"
		}
	}
	return scheme + host + path
}

var newTransport = func(hostHeader string) *http.Transport {
	return &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         hostHeader,
		},
		DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		Proxy:       http.ProxyFromEnvironment,
	}
}

var httpClient = &http.Client{
	Timeout: 5 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		Proxy:           http.ProxyFromEnvironment,
	},
}

func doRequest(rawURL string, hostHeader string) (*http.Response, []byte, error) {
	u := normalizeURL(rawURL)
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	if hostHeader != "" {
		req.Host = hostHeader
	}

	client := &http.Client{Transport: newTransport(hostHeader), Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	return resp, body, nil
}

func Fingerprint(url string) (map[string]struct{}, *http.Response, []byte) {
	client, _ := wappalyzer.New()

	resp, body, err := doRequest(url, "")
	if err != nil {
		httpURL := strings.Replace(normalizeURL(url), "https://", "http://", 1)
		resp, body, err = doRequest(httpURL, "")
		if err != nil {
			return nil, nil, nil
		}
	}

	fp := client.Fingerprint(resp.Header, body)
	if _, ok := fp["WordPress"]; !ok {
		s := string(body)
		if strings.Contains(s, "/wp-content/") || strings.Contains(s, "/wp-includes/") {
			fp["WordPress"] = struct{}{}
		}
	}
	return fp, resp, body
}

func FingerprintWithIP(ip, host string) (map[string]struct{}, *http.Response, []byte) {
	client, _ := wappalyzer.New()

	target := ip
	if parsed := net.ParseIP(strings.Trim(ip, "[]")); parsed != nil && parsed.To4() == nil {
		target = "[" + strings.Trim(ip, "[]") + "]"
	}

	resp, body, err := doRequest("https://"+target, host)
	if err != nil {
		resp, body, err = doRequest("http://"+target, host)
		if err != nil {
			return nil, nil, nil
		}
	}

	fp := client.Fingerprint(resp.Header, body)
	if _, ok := fp["WordPress"]; !ok {
		s := string(body)
		if strings.Contains(s, "/wp-content/") || strings.Contains(s, "/wp-includes/") {
			fp["WordPress"] = struct{}{}
		}
	}
	return fp, resp, body
}

func ResolveIP(domain string) string {
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.Split(domain, "/")[0]

	ips, err := net.LookupIP(domain)
	if err != nil || len(ips) == 0 {
		return ""
	}
	for _, ip := range ips {
		if ip.To4() != nil {
			return ip.String()
		}
	}
	return ips[0].String()
}

func CheckXMLRPC(rawURL string) bool {
	u := normalizeURL(rawURL)
	client := &http.Client{Timeout: 5 * time.Second, Transport: newTransport("")}

	req, err := http.NewRequest("POST", u, strings.NewReader(`<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>`))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "text/xml")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200 || resp.StatusCode == 405
}

var _ = fmt.Sprintf
