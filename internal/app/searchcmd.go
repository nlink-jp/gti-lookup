package app

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/nlink-jp/gti-lookup/internal/engine"
)

func runSearch(args []string, version string, stdout, stderr io.Writer) int {
	var common commonFlags
	var ctype, order string
	fs := flag.NewFlagSet("search", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { usage(stderr) }
	common.register(fs)
	fs.StringVar(&ctype, "type", "", "collection type ("+strings.Join(engine.CollectionTypes, ", ")+")")
	fs.StringVar(&order, "order", "", `order key (default "relevance-")`)

	positional, err := parseInterleaved(fs, args)
	if err != nil {
		return exitError
	}
	query := strings.Join(positional, " ")
	if query == "" && ctype == "" {
		fmt.Fprintln(stderr, "gti-lookup: search needs a query, --type, or both")
		return exitError
	}

	eng, err := common.buildEngine(version)
	if err != nil {
		return fail(stderr, err)
	}
	res, err := eng.SearchThreats(context.Background(), query, engine.SearchOptions{
		CollectionType: ctype,
		OrderBy:        order,
		Limit:          common.limit,
		Refresh:        common.refresh,
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

	label := res.Query
	if res.CollectionType != "" {
		label = strings.TrimSpace(res.CollectionType + " " + label)
	}
	fmt.Fprintf(stdout, "search: %s (%s)\n", label, res.OrderBy)
	fmt.Fprintln(stdout, moreLine(res.Retrieved, res.More, res.TotalUpstream))
	for _, s := range res.Threats {
		fmt.Fprintln(stdout, summaryLine(s))
	}
	if res.Retrieved == 0 {
		fmt.Fprintln(stdout, "no matching collections — a valid answer, not a failure")
	}
	return exitOK
}
