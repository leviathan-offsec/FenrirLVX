package engine

import (
	"io"
	"net/http"
	"net/mail"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var (
	emailRe     = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)
	mailtoRe    = regexp.MustCompile(`mailto:([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})`)
	priorityPre = []string{"security", "abuse", "soc", "cert", "csirt", "psirt", "contact", "info", "admin", "support", "hello"}
)

func ExtractContactEmails(body []byte, hostname string) []string {
	seen := make(map[string]bool)
	var found []string

	for _, m := range mailtoRe.FindAllStringSubmatch(string(body), -1) {
		e := strings.ToLower(m[1])
		if !seen[e] {
			seen[e] = true
			found = append(found, e)
		}
	}

	for _, e := range emailRe.FindAllString(string(body), -1) {
		e = strings.ToLower(e)
		if strings.Contains(e, "example.com") ||
			strings.Contains(e, "sentry.io") ||
			strings.Contains(e, "wixpress.com") ||
			strings.Contains(e, "@2x") ||
			strings.Contains(e, "@3x") {
			continue
		}
		if _, err := mail.ParseAddress(e); err != nil {
			continue
		}
		if !seen[e] {
			seen[e] = true
			found = append(found, e)
		}
	}

	var priority, rest []string
	for _, e := range found {
		matched := false
		for _, p := range priorityPre {
			if strings.HasPrefix(e, p+"@") || strings.Contains(e, p+"@") {
				priority = append(priority, e)
				matched = true
				break
			}
		}
		if !matched {
			rest = append(rest, e)
		}
	}

	out := append(priority, rest...)
	if len(out) > 5 {
		out = out[:5]
	}
	return out
}

func FetchSecurityTxt(baseURL string) []string {
	urls := []string{
		strings.TrimSuffix(baseURL, "/") + "/.well-known/security.txt",
		strings.TrimSuffix(baseURL, "/") + "/security.txt",
	}
	client := &http.Client{Timeout: 5 * time.Second}
	var contacts []string
	seen := make(map[string]bool)

	for _, u := range urls {
		req, err := http.NewRequest("GET", u, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
		resp, err := client.Do(req)
		if err != nil || resp.StatusCode != 200 {
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		for _, line := range strings.Split(string(body), "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(strings.ToLower(line), "contact:") {
				continue
			}
			val := strings.TrimSpace(line[len("contact:"):])
			val = strings.TrimPrefix(val, "mailto:")
			if strings.Contains(val, "@") && !seen[val] {
				seen[val] = true
				contacts = append(contacts, val)
			}
		}
	}
	return contacts
}

func BuildDisclosureLink(hostname, plugin, version, cve, cvss, title string, emails []string) string {
	if len(emails) == 0 {
		return ""
	}
	subject := "Security disclosure — " + plugin + " " + cve + " on " + hostname
	body := "Hi,\r\n\r\n" +
		"While performing routine external reconnaissance (no exploitation attempted), " +
		"I identified what appears to be an unpatched vulnerability on your WordPress site.\r\n\r\n" +
		"Target: " + hostname + "\r\n" +
		"Plugin: " + plugin + " (detected version: " + version + ")\r\n" +
		"Vulnerability: " + cve + " — CVSS " + cvss + "\r\n" +
		"Impact: " + title + "\r\n\r\n" +
		"I did not attempt to exploit this. Reporting in good faith.\r\n\r\n" +
		"CVE: https://www.cve.org/CVERecord?id=" + cve

	return "mailto:" + emails[0] +
		"?subject=" + url.QueryEscape(subject) +
		"&body=" + url.QueryEscape(body)
}
