package app

import (
	"context"
	"flag"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/nlink-jp/gti-lookup/internal/engine"
)

func runThreat(args []string, version string, stdout, stderr io.Writer) int {
	var common commonFlags
	var related, relatedOther string
	var mitre bool
	fs := flag.NewFlagSet("threat", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { usage(stderr) }
	common.register(fs)
	fs.StringVar(&related, "related", "", "expand one relationship ("+strings.Join(engine.CollectionRelationships, ", ")+")")
	fs.StringVar(&relatedOther, "related-other", "", "expand an upstream relationship the --related list does not carry")
	fs.BoolVar(&mitre, "mitre", false, "ATT&CK tree of the collection")

	positional, err := parseInterleaved(fs, args)
	if err != nil {
		return exitError
	}
	if len(positional) != 1 {
		fmt.Fprintln(stderr, "gti-lookup: threat takes exactly one collection id")
		return exitError
	}
	id := positional[0]

	eng, err := common.buildEngine(version)
	if err != nil {
		return fail(stderr, err)
	}
	ctx := context.Background()

	if mitre {
		if related != "" || relatedOther != "" {
			fmt.Fprintln(stderr, "gti-lookup: --mitre and --related are separate views; ask for one at a time")
			return exitError
		}
		res, err := eng.ThreatMitreTree(ctx, id, engine.ThreatOptions{Refresh: common.refresh})
		if err != nil {
			return fail(stderr, err)
		}
		if common.jsonOut {
			if err := renderJSON(stdout, res); err != nil {
				return fail(stderr, err)
			}
			return exitOK
		}
		renderMitre(stdout, res)
		return exitOK
	}

	if related != "" || relatedOther != "" {
		res, err := eng.ThreatRelated(ctx, id, engine.RelatedOptions{
			Relationship:      related,
			RelationshipOther: relatedOther,
			Limit:             common.limit,
			Refresh:           common.refresh,
		})
		if err != nil {
			return fail(stderr, err)
		}
		if common.jsonOut {
			if err := renderJSON(stdout, res); err != nil {
				return fail(stderr, err)
			}
			return exitOK
		}
		renderRelated(stdout, res)
		return exitOK
	}

	res, err := eng.Threat(ctx, id, engine.ThreatOptions{Refresh: common.refresh})
	if err != nil {
		return fail(stderr, err)
	}
	if common.jsonOut {
		if err := renderJSON(stdout, res); err != nil {
			return fail(stderr, err)
		}
		return exitOK
	}
	renderThreat(stdout, res)
	return exitOK
}

// renderRelated prints one relationship expansion, shared with the ioc
// command.
func renderRelated(stdout io.Writer, res *engine.Related) {
	fmt.Fprintf(stdout, "%s → %s\n", res.Subject, res.Relationship)
	fmt.Fprintln(stdout, moreLine(res.Retrieved, res.More, res.TotalUpstream))
	for _, item := range res.Items {
		line := "  " + item.ID
		if item.Name != "" {
			line = fmt.Sprintf("  %-14s %s\n      id: %s", orDash(item.CollectionType, item.Type), item.Name, item.ID)
		}
		fmt.Fprintln(stdout, line)
	}
	if res.Retrieved == 0 {
		fmt.Fprintln(stdout, "nothing related under this relationship — a valid answer, not a failure")
	}
}

// renderThreat prints a collection report: identity first, description next,
// then the remaining attributes — scalars verbatim, structures as counts.
// The text view is a summary by design; --json carries everything.
func renderThreat(stdout io.Writer, res *engine.Threat) {
	fmt.Fprintf(stdout, "%s: %s\n", orDash(res.CollectionType, "collection"), orDash(res.Name, res.ID))
	fmt.Fprintf(stdout, "id: %s\n", res.ID)

	if desc, ok := res.Attributes["description"].(string); ok && desc != "" {
		fmt.Fprintln(stdout)
		fmt.Fprintln(stdout, clip(desc, 1200, "… (--json for the full description)"))
	}

	keys := make([]string, 0, len(res.Attributes))
	for k := range res.Attributes {
		if k == "description" || k == "name" || k == "collection_type" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) > 0 {
		fmt.Fprintln(stdout)
	}
	for _, k := range keys {
		switch v := res.Attributes[k].(type) {
		case string:
			fmt.Fprintf(stdout, "%s: %s\n", k, clip(v, 200, "…"))
		case float64:
			fmt.Fprintf(stdout, "%s: %s\n", k, renderNumber(k, v))
		case bool:
			fmt.Fprintf(stdout, "%s: %t\n", k, v)
		case []any:
			fmt.Fprintf(stdout, "%s: [%d items] (--json to expand)\n", k, len(v))
		case map[string]any:
			fmt.Fprintf(stdout, "%s: {%d fields} (--json to expand)\n", k, len(v))
		}
	}
}

// renderMitre prints the tree as tactic/technique identity lines. The raw
// tree (descriptions, signatures) is --json territory.
func renderMitre(stdout io.Writer, res *engine.MitreTree) {
	fmt.Fprintf(stdout, "ATT&CK tree: %s\n", res.ID)
	tactics, _ := res.Tree["tactics"].([]any)
	if len(tactics) == 0 {
		fmt.Fprintln(stdout, "no ATT&CK techniques recorded — a valid answer, not a failure")
		return
	}
	for _, rt := range tactics {
		m, _ := rt.(map[string]any)
		if m == nil {
			continue
		}
		fmt.Fprintf(stdout, "%s %s\n", m["id"], m["name"])
		techs, _ := m["techniques"].([]any)
		for _, rtc := range techs {
			tm, _ := rtc.(map[string]any)
			if tm == nil {
				continue
			}
			if count, ok := tm["count"].(float64); ok && count > 0 {
				fmt.Fprintf(stdout, "  %-10s %s (%g)\n", tm["id"], tm["name"], count)
			} else {
				fmt.Fprintf(stdout, "  %-10s %s\n", tm["id"], tm["name"])
			}
		}
	}
	fmt.Fprintln(stdout, "(identity view; --json for descriptions and signatures)")
}

func clip(s string, max int, marker string) string {
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	return string(runes[:max]) + marker
}

func orDash(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return "-"
}
