package chat

import (
	"encoding/json"
	"path"
	"sort"
)

type Finding struct {
	File string `json:"file"`
	CWE  string `json:"cwe"`
}
type Comparison struct{ HarnessOnly, BaselineOnly, Both []Finding }

func Compare(harness []Finding, baseline []Finding) Comparison {
	a, b := map[Finding]bool{}, map[Finding]bool{}
	for _, f := range harness {
		f.File = path.Clean(f.File)
		a[f] = true
	}
	for _, f := range baseline {
		f.File = path.Clean(f.File)
		b[f] = true
	}
	c := Comparison{}
	for f := range a {
		if b[f] {
			c.Both = append(c.Both, f)
		} else {
			c.HarnessOnly = append(c.HarnessOnly, f)
		}
	}
	for f := range b {
		if !a[f] {
			c.BaselineOnly = append(c.BaselineOnly, f)
		}
	}
	for _, items := range [][]Finding{c.Both, c.HarnessOnly, c.BaselineOnly} {
		sort.Slice(items, func(i, j int) bool {
			if items[i].File == items[j].File {
				return items[i].CWE < items[j].CWE
			}
			return items[i].File < items[j].File
		})
	}
	return c
}
func parseFindings(raw json.RawMessage) []Finding {
	var items []struct {
		File string `json:"file"`
		CWE  string `json:"cwe"`
		Hops []struct {
			File string `json:"file"`
		} `json:"hops"`
	}
	if json.Unmarshal(raw, &items) != nil {
		return nil
	}
	var out []Finding
	for _, item := range items {
		file := item.File
		if file == "" && len(item.Hops) > 0 {
			file = item.Hops[0].File
		}
		if file != "" {
			out = append(out, Finding{file, item.CWE})
		}
	}
	return out
}
