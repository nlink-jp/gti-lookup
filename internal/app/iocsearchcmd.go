package app

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/nlink-jp/gti-lookup/internal/engine"
)

func runSearchIOCs(args []string, version string, stdout, stderr io.Writer) int {
	var common commonFlags
	var order string
	fs := flag.NewFlagSet("search-iocs", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { usage(stderr) }
	common.register(fs)
	fs.StringVar(&order, "order", "", `order key (e.g. last_submission_date-; empty lets upstream rank)`)

	positional, err := parseInterleaved(fs, args)
	if err != nil {
		return exitError
	}
	query := strings.Join(positional, " ")
	if query == "" {
		fmt.Fprintln(stderr, "gti-lookup: search-iocs needs a query (GTI intelligence syntax)")
		return exitError
	}

	eng, err := common.buildEngine(version)
	if err != nil {
		return fail(stderr, err)
	}
	res, err := eng.SearchIOCs(context.Background(), query, engine.IOCSearchOptions{
		OrderBy: order,
		Limit:   common.limit,
		Refresh: common.refresh,
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

	fmt.Fprintf(stdout, "search-iocs: %s\n", res.Query)
	fmt.Fprintln(stdout, moreLine(res.Retrieved, res.More, res.TotalUpstream))
	for _, item := range res.Items {
		fmt.Fprintf(stdout, "  %-10s %s\n      id: %s\n", item.Type, iocItemLabel(item), item.ID)
	}
	if res.Retrieved == 0 {
		fmt.Fprintln(stdout, "no matching indicators — a valid answer, not a failure")
	}
	return exitOK
}

// iocItemLabel picks the most human-readable identity an item carries.
func iocItemLabel(item engine.IOCItem) string {
	for _, key := range []string{"meaningful_name", "title", "url", "last_final_url"} {
		if s, ok := item.Attributes[key].(string); ok && s != "" {
			return clip(s, 80, "…")
		}
	}
	if s, ok := item.Attributes["type_description"].(string); ok && s != "" {
		return s
	}
	return "-"
}
