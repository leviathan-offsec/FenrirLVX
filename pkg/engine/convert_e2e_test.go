package engine

import "testing"

// The convertor produces year-based ranges like 2023.1.0-2023.10.5. Before the
// semver fix, looksLikeVersion rejected these outright, so the plugin was never
// correlated at all. End-to-end check against a converted entry.
func TestConvertedYearRangeIsCorrelated(t *testing.T) {
	db := VulnDB{
		"dated-plugin": {{
			ID: "TEST-1", CVSS: 8.1,
			From: "2023.1.0", FromInclusive: true,
			To: "2023.10.5", ToInclusive: true,
		}},
	}
	plugins := map[string]string{"dated-plugin": "2023.5.0"}
	cov := SummarizeCoverage(plugins, db, true)
	if len(cov.NoVersion) != 0 {
		t.Errorf("2023.5.0 was treated as unreadable: %v", cov.NoVersion)
	}
	got := CheckVulns(plugins, db, true)
	if len(got["dated-plugin"]) != 1 {
		t.Errorf("year-versioned plugin was not correlated: %v", got)
	}
}
