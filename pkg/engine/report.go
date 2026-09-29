package engine

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	ansiReset = "\033[0m"
	ansiCyan  = "\033[36m"
	ansiGreen = "\033[32m"
	ansiRed   = "\033[31m"
	ansiYellow = "\033[33m"
	ansiWhite = "\033[37m"
)

type Finding struct {
	Target       string
	Hostname     string
	IP           string
	StatusCode   int
	ServerHeader string
	TechStack    []string
	Plugins      map[string]string
	Themes       []string
	Vulns        map[string][]VulnEntry
	Honeypot     bool
	HoneypotWhy  string
	Emails       []string
	ScanDuration time.Duration
	FetchedAt    time.Time
}

func (f *Finding) TopSeverity() float64 {
	top := 0.0
	for _, entries := range f.Vulns {
		for _, e := range entries {
			if e.CVSS > top {
				top = e.CVSS
			}
		}
	}
	return top
}

func (f *Finding) VulnCount() int {
	n := 0
	for _, entries := range f.Vulns {
		n += len(entries)
	}
	return n
}

func (f *Finding) AllVulns() []VulnEntry {
	var all []VulnEntry
	for _, entries := range f.Vulns {
		all = append(all, entries...)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].CVSS > all[j].CVSS })
	return all
}

func (f *Finding) Display(confidence int, changelogHits int) string {
	var sb strings.Builder
	header := f.Target
	if f.Hostname != "" && f.Hostname != f.Target {
		header = f.Hostname + " (" + f.IP + ")"
	}
	if f.Honeypot {
		fmt.Fprintf(&sb, "%s[SKIP]%s %s — honeypot: %s\n", ansiYellow, ansiReset, header, f.HoneypotWhy)
		return sb.String()
	}
	if f.VulnCount() == 0 {
		fmt.Fprintf(&sb, "%s[+]%s %sClean%s: %s\n", ansiGreen, ansiReset, ansiGreen, ansiReset, header)
		return sb.String()
	}
	marker := "~"
	switch {
	case confidence >= 80:
		marker = "!!!"
	case confidence >= 60:
		marker = "!!"
	case confidence >= 40:
		marker = "!"
	}
	markerColor := ansiYellow
	if confidence >= 80 {
		markerColor = ansiRed
	}
	fmt.Fprintf(&sb, "%s[%s]%s %s%s%s  confidence=%d/100  changelog=%d\n",
		markerColor, marker, ansiReset, header, markerColor, ansiReset, confidence, changelogHits)
	if len(f.Plugins) > 0 {
		plugins := make([]string, 0, len(f.Plugins))
		for p, v := range f.Plugins {
			plugins = append(plugins, p+" "+v)
		}
		sort.Strings(plugins)
		fmt.Fprintf(&sb, "    %splugins%s  %s\n", ansiCyan, ansiReset, strings.Join(plugins, ", "))
	}
	if f.ServerHeader != "" || f.StatusCode != 0 {
		fmt.Fprintf(&sb, "    %sserver%s   %s [%d]\n", ansiCyan, ansiReset, f.ServerHeader, f.StatusCode)
	}
	fmt.Fprintf(&sb, "    %sfindings%s\n", ansiWhite, ansiReset)
	plugins := make([]string, 0, len(f.Vulns))
	for plugin := range f.Vulns {
		plugins = append(plugins, plugin)
	}
	sort.Strings(plugins)
	for _, plugin := range plugins {
		entries := f.Vulns[plugin]
		sort.Slice(entries, func(i, j int) bool { return entries[i].CVSS > entries[j].CVSS })
		show := 2
		if len(entries) < show {
			show = len(entries)
		}
		for i := 0; i < show; i++ {
			e := entries[i]
			m := "  "
			if e.CVSS >= 9.0 {
				m = "!!"
			} else if e.CVSS >= 7.0 {
				m = "! "
			} else if e.CVSS >= 4.0 {
				m = "~ "
			}
			severityColor := ansiYellow
			if e.CVSS >= 9.0 {
				severityColor = ansiRed
			}
			fmt.Fprintf(&sb, "      %s%s%s  %.1f%s  %s%s%s  %s\n",
				severityColor, m, ansiReset, e.CVSS, ansiReset, ansiCyan, e.ID, ansiReset, e.Title)
		}
		if len(entries) > show {
			fmt.Fprintf(&sb, "      %s... +%d more (%s)%s\n", ansiCyan, len(entries)-show, plugin, ansiReset)
		}
	}
	if len(f.Emails) > 0 {
		fmt.Fprintf(&sb, "    %sreport%s    %s\n", ansiCyan, ansiReset, f.Emails[0])
	}
	return sb.String()
}
