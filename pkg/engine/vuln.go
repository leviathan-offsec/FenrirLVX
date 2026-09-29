package engine

import (
	"encoding/json"
	"os"
	"sort"
)

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

func LoadVulnDB(path string) (VulnDB, error) {
	var db VulnDB
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(data, &db)
	return db, err
}

func CheckVulns(plugins map[string]string, db VulnDB, precision bool) map[string][]VulnEntry {
	findings := make(map[string][]VulnEntry)
	for plugin, version := range plugins {
		entries, ok := db[plugin]
		if !ok {
			continue
		}
		for _, e := range entries {
			if inRange(version, e.From, e.To, e.FromInclusive, e.ToInclusive) {
				findings[plugin] = append(findings[plugin], e)
			} else if !precision && (version == "unknown" || version == "") {
				findings[plugin] = append(findings[plugin], e)
			}
		}
	}
	// Dedup by ID
	for k, list := range findings {
		seen := make(map[string]bool)
		var unique []VulnEntry
		for _, e := range list {
			if !seen[e.ID] {
				seen[e.ID] = true
				unique = append(unique, e)
			}
		}
		findings[k] = unique
	}
	return findings
}

func SortByCVSS(vulns []VulnEntry) []VulnEntry {
	out := make([]VulnEntry, len(vulns))
	copy(out, vulns)
	sort.Slice(out, func(i, j int) bool { return out[i].CVSS > out[j].CVSS })
	return out
}

func TopCVEs(vulns []VulnEntry, n int) []VulnEntry {
	sorted := SortByCVSS(vulns)
	if len(sorted) > n {
		return sorted[:n]
	}
	return sorted
}
