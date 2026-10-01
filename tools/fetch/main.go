package main

// fetch_wordfence.go pulls vulnerability records from the Wordfence
// Intelligence API and writes them in the shape tools/convertor.go expects:
// a top-level object keyed by record id, each value a record object.
//
// The 158 MB export was previously committed-by-hand and shipped inside every
// release archive, which made each platform zip ~17 MB and meant nobody but the
// original author could reproduce a build. This fetches the same data on demand
// and the convertor distils it to the ~10 MB vuln_db.json that actually ships.
//
// Usage:
//   WORDfENCE_API_KEY=... go run ./tools/fetch_wordfence.go -out wordfence_production.json
//
// The key is read from the environment or ./.secrets/wordfence.env. It is never
// written to the output and never logged.

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	// v3 is the current version. v1 and v2 both return 410 Gone.
	baseURL   = "https://www.wordfence.com/api/intelligence/v3/vulnerabilities/scanner"
	pageSize  = 1000
	timeout   = 90 * time.Second
	retries   = 3
	retryWait = 5 * time.Second
)

// loadKey reads the API key from the environment, falling back to
// .secrets/wordfence.env so it need not end up in shell history.
func loadKey() string {
	if k := strings.TrimSpace(os.Getenv("WORDfENCE_API_KEY")); k != "" {
		return k
	}
	for _, p := range []string{".secrets/wordfence.env", "../.secrets/wordfence.env"} {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if strings.HasPrefix(line, "#") || line == "" {
				continue
			}
			if strings.HasPrefix(line, "WORDfENCE_API_KEY=") {
				return strings.Trim(strings.TrimPrefix(line, "WORDfENCE_API_KEY="), `"'`)
			}
		}
	}
	return ""
}

// fetchPage gets one page. The API returns {"Items": [...], "NextPageToken": "..."}
// for the scanner endpoint; both casings are tolerated because the field name
// has varied across API revisions.
func fetchPage(client *http.Client, key, token string) ([]json.RawMessage, string, error) {
	// The scanner endpoint is GET-only; POST returns 405. Pagination is by the
	// next-page token in the body, not by a request body.
	req, err := http.NewRequest(http.MethodGet, baseURL, nil)
	if err != nil {
		return nil, "", err
	}
	// v3 requires a Bearer token; "Token <key>" returns 401.
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Accept", "application/json")
	if token != "" {
		q := req.URL.Query()
		q.Set("page", token)
		req.URL.RawQuery = q.Encode()
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
		return nil, "", fmt.Errorf("API returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var raw map[string]json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, "", err
	}

	// Items may be capitalised or not depending on revision.
	var items []json.RawMessage
	for _, key := range []string{"Items", "items"} {
		if v, ok := raw[key]; ok {
			if err := json.Unmarshal(v, &items); err != nil {
				return nil, "", err
			}
			break
		}
	}

	var next string
	for _, key := range []string{"NextPageToken", "nextPageToken"} {
		if v, ok := raw[key]; ok {
			_ = json.Unmarshal(v, &next)
			break
		}
	}
	return items, next, nil
}

func main() {
	out := flag.String("out", "wordfence_production.json", "output path")
	maxPages := flag.Int("pages", 0, "stop after N pages (0 = all)")
	flag.Parse()

	key := loadKey()
	if key == "" {
		fmt.Fprintln(os.Stderr, "[!] No API key. Set WORDfENCE_API_KEY or create .secrets/wordfence.env")
		os.Exit(1)
	}

	client := &http.Client{Timeout: timeout}

	// The convertor walks a top-level object of records, so build exactly that:
	// {"<id>": {<record>}, ...}
	outFile, err := os.Create(*out)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] %v\n", err)
		os.Exit(1)
	}
	defer outFile.Close()

	w := bufio.NewWriterSize(outFile, 1<<20)
	defer w.Flush()

	if _, err := w.WriteString("{\n"); err != nil {
		fmt.Fprintf(os.Stderr, "[!] %v\n", err)
		os.Exit(1)
	}

	total := 0
	first := true
	token := ""

	for page := 0; ; page++ {
		if *maxPages > 0 && page >= *maxPages {
			break
		}

		items, next, err := fetchPage(client, key, token)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] page %d: %v\n", page, err)
			os.Exit(1)
		}
		if len(items) == 0 {
			break
		}

		for i, item := range items {
			var rec struct {
				ID string `json:"id"`
			}
			_ = json.Unmarshal(item, &rec)

			key := rec.ID
			if key == "" {
				key = fmt.Sprintf("row-%d-%d", page, i)
			}
			if !first {
				if _, err := w.WriteString(",\n"); err != nil {
					fmt.Fprintf(os.Stderr, "[!] %v\n", err)
					os.Exit(1)
				}
			}
			first = false
			fmt.Fprintf(w, "  %q: ", key)
			if _, err := w.Write(item); err != nil {
				fmt.Fprintf(os.Stderr, "[!] %v\n", err)
				os.Exit(1)
			}
			total++
		}

		fmt.Fprintf(os.Stderr, "[+] page %d: %d records (total %d)\n", page+1, len(items), total)

		if next == "" {
			break
		}
		token = next
		time.Sleep(200 * time.Millisecond)
	}

	if _, err := w.WriteString("\n}\n"); err != nil {
		fmt.Fprintf(os.Stderr, "[!] %v\n", err)
		os.Exit(1)
	}

	size := "unknown"
	if st, err := os.Stat(*out); err == nil {
		size = fmt.Sprintf("%.1f MB", float64(st.Size())/1024/1024)
	}
	fmt.Fprintf(os.Stderr, "[+] wrote %d records to %s (%s)\n", total, *out, size)
	fmt.Fprintln(os.Stderr, "[+] next: go run ./tools/convertor.go")
	fmt.Fprintln(os.Stderr, "    then rebuild, and the release zip drops from ~17MB to ~5MB")
	_ = filepath.Base(*out)
}
