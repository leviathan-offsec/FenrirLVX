package engine

import (
	"strings"
	"testing"
)

func testDB() VulnDB {
	return VulnDB{
		"akismet": {
			{ID: "CVE-2020-1", CVSS: 5.3, Title: "bounded", From: "1.0", FromInclusive: true, To: "4.0", ToInclusive: true},
		},
		"broken-plugin": {
			// No upper bound: matches every version ever reported. This is the
			// shape that inflates results against real Wordfence data.
			{ID: "CVE-9999-1", CVSS: 9.8, Title: "unbounded", From: "*", To: "*"},
		},
		"bounded-hi": {
			{ID: "CVE-8888-1", CVSS: 7.5, Title: "recent", From: "5.0", FromInclusive: true, To: "6.0", ToInclusive: true},
		},
	}
}

// A plugin with no advisory data must be visible as a coverage gap, not
// silently dropped. This is the whole point: silent drops make an offline scan
// indistinguishable from a clean one.
func TestCoverageFlagsUnmatchedPlugins(t *testing.T) {
	plugins := map[string]string{
		"akismet":       "4.1",   // in DB, out of range
		"jetpack":       "10.0",  // not in DB at all
		"broken-plugin": "1.2.3", // in DB, unbounded
		"bounded-hi":    "5.5",   // in DB, in range
	}

	cov := SummarizeCoverage(plugins, testDB(), true)

	if cov.Detected != 4 {
		t.Fatalf("Detected = %d, want 4", cov.Detected)
	}
	if cov.Matched != 3 {
		t.Errorf("Matched = %d, want 3 (akismet, broken-plugin, bounded-hi)", cov.Matched)
	}
	if len(cov.Unmatched) != 1 || cov.Unmatched[0] != "jetpack" {
		t.Errorf("Unmatched = %v, want [jetpack]", cov.Unmatched)
	}
	// broken-plugin matched on an unbounded advisory, so it must be called out.
	if len(cov.UnknownRange) != 1 || cov.UnknownRange[0] != "broken-plugin" {
		t.Errorf("UnknownRange = %v, want [broken-plugin]", cov.UnknownRange)
	}
}

func TestCoverageFlagsUnreadableVersions(t *testing.T) {
	plugins := map[string]string{
		"akismet": "not-a-version",
	}
	cov := SummarizeCoverage(plugins, testDB(), true)
	if len(cov.NoVersion) != 1 || cov.NoVersion[0] != "akismet" {
		t.Errorf("NoVersion = %v, want [akismet]", cov.NoVersion)
	}
}

func TestAnalyzeCarriesEvidence(t *testing.T) {
	plugins := map[string]string{"bounded-hi": "5.5", "broken-plugin": "1.0.0"}
	m := Analyze(plugins, testDB(), true)

	hit, ok := m["bounded-hi"]
	if !ok || len(hit) == 0 {
		t.Fatalf("expected a match for bounded-hi, got %v", m)
	}
	if hit[0].Entry.ID != "CVE-8888-1" {
		t.Errorf("ID = %s, want CVE-8888-1", hit[0].Entry.ID)
	}
	if hit[0].Detected != "5.5" {
		t.Errorf("Detected = %q, want 5.5 - the version is the evidence", hit[0].Detected)
	}
	if hit[0].Unbounded {
		t.Error("a 5.0-6.0 advisory must not be flagged unbounded")
	}

	un, ok := m["broken-plugin"]
	if !ok || len(un) == 0 {
		t.Fatalf("expected a match for broken-plugin")
	}
	if !un[0].Unbounded {
		t.Error("a */* advisory must be flagged Unbounded so the report can say so")
	}
}

// Precision mode must not fire on an unreadable version. The offline mode may,
// but has to admit it did.
func TestUnknownVersionPrecision(t *testing.T) {
	plugins := map[string]string{"akismet": "unknown"}
	db := testDB()

	if got := CheckVulns(plugins, db, true); len(got) != 0 {
		t.Errorf("precision mode fired on an unknown version: %v", got)
	}

	got := CheckVulns(plugins, db, false)
	if len(got) == 0 {
		t.Fatal("non-precision mode should still report, but mark it fuzzy")
	}
	m := Analyze(plugins, db, false)
	if !m["akismet"][0].ByFuzzy {
		t.Error("a version-less match must be marked ByFuzzy")
	}
}

func TestCheckVulnsBackCompat(t *testing.T) {
	plugins := map[string]string{"bounded-hi": "5.5"}
	got := CheckVulns(plugins, testDB(), true)
	if len(got["bounded-hi"]) != 1 || got["bounded-hi"][0].ID != "CVE-8888-1" {
		t.Errorf("CheckVulns shape changed: %v", got)
	}
}

func TestInRangeBoundaries(t *testing.T) {
	cases := []struct {
		version        string
		from, to       string
		fromInc, toInc bool
		want           bool
	}{
		{"5.0", "5.0", "6.0", true, true, true},
		{"4.9", "5.0", "6.0", true, true, false},
		{"6.0", "5.0", "6.0", true, false, false}, // to exclusive
		{"6.0", "5.0", "6.0", true, true, true},
		{"5.5", "*", "*", false, false, true},
		{"5.5", "", "6.0", false, true, true},
		{"", "1.0", "6.0", true, true, false},
		{"unknown", "1.0", "6.0", true, true, false},
	}
	for _, c := range cases {
		if got := inRange(c.version, c.from, c.to, c.fromInc, c.toInc); got != c.want {
			t.Errorf("inRange(%q, %q..%q, inc=%v/%v) = %v, want %v",
				c.version, c.from, c.to, c.fromInc, c.toInc, got, c.want)
		}
	}
}

// WordPress plugin versions are not semver. Digits-only parsing means junk
// compares as a real version, so this documents the known sharp edge rather
// than pretending it is handled.
func TestLooksLikeVersionRejectsJunk(t *testing.T) {
	bad := []string{"", "unknown", "beta", "5.8-beta", "v2.1.3", strings.Repeat("9", 40)}
	for _, v := range bad {
		if looksLikeVersion(v) {
			t.Errorf("looksLikeVersion(%q) = true, want false", v)
		}
	}
	for _, v := range []string{"1.0", "5.8.1", "2023.10.1"} {
		if !looksLikeVersion(v) {
			t.Errorf("looksLikeVersion(%q) = false, want true", v)
		}
	}
}

// A clean verdict must still disclose the gap. Silence is what makes an offline
// scan untrustworthy, so the coverage line has to appear on the no-findings
// path too.
func TestDisplayCleanStillShowsCoverage(t *testing.T) {
	f := Finding{
		Target:  "example.test",
		Plugins: map[string]string{"akismet": "4.1", "jetpack": "10.0"},
		Coverage: Coverage{
			Detected:  2,
			Matched:   1,
			Unmatched: []string{"jetpack"},
		},
	}
	out := stripANSI(f.Display(0, 0))
	if !strings.Contains(out, "Clean") {
		t.Errorf("expected a clean verdict:\n%s", out)
	}
	if !strings.Contains(out, "1/2 plugins matched") {
		t.Errorf("clean verdict must disclose database coverage:\n%s", out)
	}
	if !strings.Contains(out, "1 with no advisory data") {
		t.Errorf("must say how many plugins had no data:\n%s", out)
	}
}

func stripANSI(s string) string {
	var out strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == 0x1b {
			for i < len(s) && s[i] != 'm' {
				i++
			}
			continue
		}
		out.WriteByte(s[i])
	}
	return out.String()
}
