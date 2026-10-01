package main

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
)

type WFRecord struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	CVE   string `json:"cve"`
	CVSS  struct {
		Score float64 `json:"score"`
	} `json:"cvss"`
	Software []struct {
		Type             string `json:"type"`
		Slug             string `json:"slug"`
		AffectedVersions map[string]struct {
			FromVersion   string `json:"from_version"`
			FromInclusive bool   `json:"from_inclusive"`
			ToVersion     string `json:"to_version"`
			ToInclusive   bool   `json:"to_inclusive"`
		} `json:"affected_versions"`
	} `json:"software"`
	References []string `json:"references"`
}

type VulnEntry struct {
	ID            string  `json:"id"`
	CVSS          float64 `json:"cvss"`
	Title         string  `json:"title"`
	From          string  `json:"from"`
	FromInclusive bool    `json:"from_inclusive"`
	To            string  `json:"to"`
	ToInclusive   bool    `json:"to_inclusive"`
	Patched       string  `json:"patched"`
}

type VulnDB map[string][]VulnEntry

func extractCVE(rec WFRecord) string {
	if rec.CVE != "" {
		return strings.ToUpper(rec.CVE)
	}
	re := regexp.MustCompile(`(?i)CVE-\d{4}-\d+`)
	if m := re.FindString(rec.Title); m != "" {
		return strings.ToUpper(m)
	}
	for _, u := range rec.References {
		if m := re.FindString(u); m != "" {
			return strings.ToUpper(m)
		}
	}
	return "WF-" + rec.ID
}

func main() {
	f, err := os.Open("wordfence_production.json")
	if err != nil {
		fmt.Println("[-] Cannot open wordfence_production.json:", err)
		os.Exit(1)
	}
	defer f.Close()

	decoder := json.NewDecoder(f)
	t, err := decoder.Token()
	if err != nil {
		fmt.Println("[-] Cannot read top-level token:", err)
		os.Exit(1)
	}
	if delim, ok := t.(json.Delim); !ok || delim != '{' {
		fmt.Println("[-] Expected top-level object.")
		os.Exit(1)
	}

	db := make(VulnDB)
	records := 0
	// Records that failed to decode are counted, not skipped in silence. A
	// record that vanishes here becomes a plugin with no advisory data at scan
	// time, which reads exactly like a clean plugin. This tool exists to stop
	// that from being invisible, so it does not do it to itself.
	skipped := 0
	noCVE := 0
	firstErr := error(nil)

	for decoder.More() {
		_, _ = decoder.Token()

		var rec WFRecord
		if err := decoder.Decode(&rec); err != nil {
			skipped++
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		records++

		cve := extractCVE(rec)
		if strings.HasPrefix(cve, "WF-") {
			noCVE++
		}

		for _, sw := range rec.Software {
			if sw.Slug == "" {
				continue
			}
			for _, rd := range sw.AffectedVersions {
				from := rd.FromVersion
				to := rd.ToVersion
				if from == "" {
					from = "*"
				}
				if to == "" {
					to = "*"
				}
				entry := VulnEntry{
					ID:            cve,
					CVSS:          rec.CVSS.Score,
					Title:         rec.Title,
					From:          from,
					FromInclusive: rd.FromInclusive,
					To:            to,
					ToInclusive:   rd.ToInclusive,
					Patched:       "", // optional; fill from patched_versions if desired
				}
				dup := false
				for _, x := range db[sw.Slug] {
					if x.ID == entry.ID && x.From == entry.From && x.To == entry.To {
						dup = true
						break
					}
				}
				if !dup {
					db[sw.Slug] = append(db[sw.Slug], entry)
				}
			}
		}
	}

	fmt.Printf("[+] Parsed %d records -> %d plugins\n", records, len(db))

	// Coverage disclosure, same shape the scanner prints at run time.
	if skipped > 0 {
		fmt.Printf("[!] %d records failed to decode and are NOT in the database\n", skipped)
		if firstErr != nil {
			fmt.Printf("    first error: %v\n", firstErr)
		}
	}
	if noCVE > 0 {
		fmt.Printf("[!] %d records carry no CVE id, keyed as WF-<id> instead\n", noCVE)
	}

	// os.Create returns a nil file on error. Ignoring that turns a permission
	// problem into a nil dereference further down, or into an empty database
	// that the scanner later reads as "no vulnerabilities here".
	out, err := os.Create("vuln_db.json")
	if err != nil {
		fmt.Println("[-] Cannot create vuln_db.json:", err)
		os.Exit(1)
	}

	enc := json.NewEncoder(out)
	// An unchecked Encode on a full disk writes a truncated JSON file and then
	// prints success. The next scan reads that file, matches nothing, and
	// reports low coverage that looks like a real result.
	if err := enc.Encode(db); err != nil {
		out.Close()
		fmt.Println("[-] Failed writing vuln_db.json:", err)
		fmt.Println("[-] Refusing to leave a partial database in place.")
		os.Remove("vuln_db.json")
		os.Exit(1)
	}

	// Close is where a deferred write actually fails, so it is checked rather
	// than deferred-and-ignored.
	if err := out.Close(); err != nil {
		fmt.Println("[-] Failed closing vuln_db.json:", err)
		os.Remove("vuln_db.json")
		os.Exit(1)
	}

	fmt.Println("[+] Wrote vuln_db.json")
}
