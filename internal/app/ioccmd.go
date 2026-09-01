package app

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/nlink-jp/gti-lookup/internal/engine"
)

func runIOC(args []string, version string, stdout, stderr io.Writer) int {
	var common commonFlags
	var full bool
	var related, relatedOther string
	fs := flag.NewFlagSet("ioc", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { usage(stderr) }
	common.register(fs)
	fs.BoolVar(&full, "full", false, "full report instead of the trimmed actor context")
	fs.StringVar(&related, "related", "", "expand one relationship ("+strings.Join(engine.IOCRelationships, ", ")+")")
	fs.StringVar(&relatedOther, "related-other", "", "expand an upstream relationship the --related list does not carry")

	positional, err := parseInterleaved(fs, args)
	if err != nil {
		return exitError
	}
	if len(positional) == 0 {
		fmt.Fprintln(stderr, "gti-lookup: ioc takes at least one indicator (hash, IP, domain, or URL)")
		return exitError
	}
	if (related != "" || relatedOther != "") && len(positional) != 1 {
		fmt.Fprintln(stderr, "gti-lookup: --related expands one indicator at a time")
		return exitError
	}

	eng, err := common.buildEngine(version)
	if err != nil {
		return fail(stderr, err)
	}
	ctx := context.Background()

	if related != "" || relatedOther != "" {
		res, err := eng.IOCRelated(ctx, positional[0], engine.RelatedOptions{
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

	// Several indicators are looked up in sequence: JSONL when --json (one
	// document per indicator), blocks in text. One failed target never hides
	// the others — it is reported and turns the exit partial.
	exit := exitOK
	jsonl := json.NewEncoder(stdout)
	for i, value := range positional {
		res, err := eng.LookupIOC(ctx, value, engine.IOCOptions{
			Full:    full,
			Limit:   common.limit,
			Refresh: common.refresh,
		})
		if err != nil {
			if code := exitFor(err); code == exitError && len(positional) == 1 {
				return fail(stderr, err)
			}
			fmt.Fprintf(stderr, "gti-lookup: %s: [%s] %v\n", value, engine.Code(err), err)
			exit = exitPartial
			continue
		}
		if common.jsonOut {
			if err := jsonl.Encode(res); err != nil {
				return fail(stderr, err)
			}
		} else {
			if i > 0 {
				fmt.Fprintln(stdout)
			}
			renderIOC(stdout, res)
		}
		if res.Incomplete {
			exit = exitPartial
		}
	}
	return exit
}

// renderIOC prints one indicator's actor context. An incomplete answer leads
// with INCONCLUSIVE — an empty association list built on a failed expansion
// must never read as "clean".
func renderIOC(stdout io.Writer, res *engine.IOC) {
	fmt.Fprintf(stdout, "%s (%s)\n", res.Value, res.Kind)
	if res.Incomplete {
		fmt.Fprintf(stdout, "INCONCLUSIVE: %s\n", res.Note)
	}

	if len(res.Assessment) > 0 {
		fmt.Fprintln(stdout, "gti_assessment:")
		renderScalars(stdout, "  ", res.Assessment)
	}

	if scalars := scalarCount(res.Attributes); scalars > 0 {
		fmt.Fprintln(stdout, "attributes:")
		renderScalars(stdout, "  ", res.Attributes)
	}

	if !res.Incomplete {
		fmt.Fprintf(stdout, "associations: %s\n", moreLine(res.AssociationsRetrieved, res.AssociationsMore, res.AssociationsUpstream))
		for _, s := range res.Associations {
			fmt.Fprintln(stdout, summaryLine(s))
		}
		if res.AssociationsRetrieved == 0 {
			fmt.Fprintln(stdout, "  no curated threat names this indicator — a valid answer, not a failure")
		}
	}
}

// renderScalars prints a map's scalar fields sorted, one level of nesting
// deep; deeper structures are shown as counts (--json expands them).
func renderScalars(stdout io.Writer, indent string, m map[string]any) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		switch v := m[k].(type) {
		case string:
			fmt.Fprintf(stdout, "%s%s: %s\n", indent, k, clip(v, 200, "…"))
		case float64:
			fmt.Fprintf(stdout, "%s%s: %g\n", indent, k, v)
		case bool:
			fmt.Fprintf(stdout, "%s%s: %t\n", indent, k, v)
		case map[string]any:
			if s, ok := singleScalar(v); ok {
				fmt.Fprintf(stdout, "%s%s: %s\n", indent, k, s)
			} else {
				fmt.Fprintf(stdout, "%s%s: {%d fields} (--json to expand)\n", indent, k, len(v))
			}
		case []any:
			fmt.Fprintf(stdout, "%s%s: [%d items] (--json to expand)\n", indent, k, len(v))
		}
	}
}

// singleScalar unwraps GTI's {"value": X} wrapper objects so a verdict prints
// as one line instead of "{1 fields}".
func singleScalar(m map[string]any) (string, bool) {
	if len(m) != 1 {
		return "", false
	}
	for _, v := range m {
		switch s := v.(type) {
		case string:
			return s, true
		case float64:
			return fmt.Sprintf("%g", s), true
		case bool:
			return fmt.Sprintf("%t", s), true
		}
	}
	return "", false
}

func scalarCount(m map[string]any) int {
	n := 0
	for _, v := range m {
		switch v.(type) {
		case string, float64, bool:
			n++
		}
	}
	return n
}
