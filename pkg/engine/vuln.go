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

// Coverage records how much of what was detected the database could actually
// speak to. Without this, a plugin missing from the DB and a clean plugin
// produce identical output, which makes an offline scan untrustworthy.
type Coverage struct {
	Detected     int      // plugins found on the target
	Matched      int      // plugins present in the database
	Unmatched    []string // slugs with no advisory data, sorted
	NoVersion    []string // matched but version unreadable, so range not applied
	UnknownRange []string // matched on an unbounded advisory
}

// Match is one hit plus the reason it fired, so a finding can be audited
// without re-running the scan.
type Match struct {
	Entry     VulnEntry
	Plugin    string
	Detected  string // version string as read off the target
	Unbounded bool   // advisory had "*" on the From or To bound
	ByFuzzy   bool   // matched because version was unknown, not by range
}

func CheckVulns(plugins map[string]string, db VulnDB, precision bool) map[string][]VulnEntry {
	out := make(map[string][]VulnEntry)
	for plugin, m := range Analyze(plugins, db, precision) {
		list := make([]VulnEntry, 0, len(m))
		for _, hit := range m {
			list = append(list, hit.Entry)
		}
		if len(list) > 0 {
			out[plugin] = list
		}
	}
	return out
}

// Analyze is CheckVulns with the reasoning attached. Callers that report to a
// human should use this; CheckVulns stays for the existing call sites.
func Analyze(plugins map[string]string, db VulnDB, precision bool) map[string][]Match {
	findings := make(map[string][]Match)
	for plugin, version := range plugins {
		entries, ok := db[plugin]
		if !ok {
			continue
		}
		for _, e := range entries {
			unbounded := isUnbounded(e)
			if inRange(version, e.From, e.To, e.FromInclusive, e.ToInclusive) {
				findings[plugin] = append(findings[plugin], Match{
					Entry:     e,
					Plugin:    plugin,
					Detected:  version,
					Unbounded: unbounded,
				})
			} else if !precision && (version == "unknown" || version == "") {
				findings[plugin] = append(findings[plugin], Match{
					Entry:     e,
					Plugin:    plugin,
					Detected:  version,
					Unbounded: unbounded,
					ByFuzzy:   true,
				})
			}
		}
	}
	// Dedup by ID, keep the first (any) match for a given CVE.
	for k, list := range findings {
		seen := make(map[string]bool)
		var unique []Match
		for _, m := range list {
			if !seen[m.Entry.ID] {
				seen[m.Entry.ID] = true
				unique = append(unique, m)
			}
		}
		findings[k] = unique
	}
	return findings
}

func isUnbounded(e VulnEntry) bool {
	return e.From == "" || e.From == "*" || e.To == "" || e.To == "*"
}

// SummarizeCoverage explains what the database could and could not speak to.
func SummarizeCoverage(plugins map[string]string, db VulnDB, precision bool) Coverage {
	cov := Coverage{Detected: len(plugins)}
	unknownVer := map[string]bool{}
	for plugin, version := range plugins {
		entries, ok := db[plugin]
		if !ok {
			cov.Unmatched = append(cov.Unmatched, plugin)
			continue
		}
		cov.Matched++
		if !looksLikeVersion(version) {
			unknownVer[plugin] = true
			continue
		}
		for _, e := range entries {
			if isUnbounded(e) {
				cov.UnknownRange = append(cov.UnknownRange, plugin)
				break
			}
		}
	}
	for p := range unknownVer {
		cov.NoVersion = append(cov.NoVersion, p)
	}
	sort.Strings(cov.Unmatched)
	sort.Strings(cov.NoVersion)
	sort.Strings(cov.UnknownRange)
	return cov
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
