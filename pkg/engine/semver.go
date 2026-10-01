package engine

import (
	"regexp"
	"strconv"
	"strings"
)

func parseSemver(v string) [4]int {
	var out [4]int
	if i := strings.IndexAny(v, "-+"); i != -1 {
		v = v[:i]
	}
	parts := strings.Split(v, ".")
	for i := 0; i < len(parts) && i < 4; i++ {
		n, err := strconv.Atoi(strings.TrimSpace(parts[i]))
		if err == nil {
			out[i] = n
		}
	}
	return out
}

func compareSemver(a, b [4]int) int {
	for i := 0; i < 4; i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	return 0
}

func inRange(version, from, to string, fromInc, toInc bool) bool {
	if version == "" || version == "unknown" {
		return false
	}
	v := parseSemver(version)

	if from != "" && from != "*" {
		cmp := compareSemver(v, parseSemver(from))
		if cmp < 0 {
			return false
		}
		if cmp == 0 && !fromInc {
			return false
		}
	}
	if to != "" && to != "*" {
		cmp := compareSemver(v, parseSemver(to))
		if cmp > 0 {
			return false
		}
		if cmp == 0 && !toInc {
			return false
		}
	}
	return true
}

var semverRe = regexp.MustCompile(`^[0-9][0-9.]*$`)

func looksLikeVersion(v string) bool {
	if v == "" || v == "unknown" {
		return false
	}
	if !semverRe.MatchString(v) {
		return false
	}
	parts := strings.Split(v, ".")
	if len(parts) > 4 {
		return false
	}
	for _, p := range parts {
		if len(p) >= 5 {
			return false
		}
	}
	if _, err := strconv.Atoi(parts[0]); err != nil {
		return false
	}
	// WordPress plugins use year-based versioning (2023.10.1, 2024.1), so a
	// major component above 30 is not on its own a reason to reject. The
	// earlier cap silently dropped those plugins from correlation, which is
	// worse than a loose parse: a missed plugin looks like a clean one.
	return true
}
