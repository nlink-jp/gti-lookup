package app

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"

	"github.com/nlink-jp/gti-lookup/internal/engine"
)

func runBehaviour(args []string, version string, stdout, stderr io.Writer) int {
	var common commonFlags
	var section string
	var offset int
	fs := flag.NewFlagSet("behaviour", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { usage(stderr) }
	common.register(fs)
	fs.StringVar(&section, "section", "", "one section from the index (e.g. dns_lookups)")
	fs.IntVar(&offset, "offset", 0, "items to skip inside the section")

	positional, err := parseInterleaved(fs, args)
	if err != nil {
		return exitError
	}
	if len(positional) != 1 {
		fmt.Fprintln(stderr, "gti-lookup: behaviour takes exactly one file hash")
		return exitError
	}

	eng, err := common.buildEngine(version)
	if err != nil {
		return fail(stderr, err)
	}
	res, err := eng.FileBehaviour(context.Background(), positional[0], engine.BehaviourOptions{
		Section: section,
		Offset:  offset,
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

	if res.Section == "" {
		fmt.Fprintf(stdout, "behaviour summary: %s\n", res.Value)
		if len(res.Summary) > 0 {
			renderScalars(stdout, "  ", res.Summary)
		}
		fmt.Fprintln(stdout, "sections (expand one with --section <name>):")
		for _, s := range res.Sections {
			fmt.Fprintf(stdout, "  %-36s %d\n", s.Name, s.Items)
		}
		if len(res.Sections) == 0 {
			fmt.Fprintln(stdout, "  (none — no sandbox has run this file)")
		}
		return exitOK
	}

	fmt.Fprintf(stdout, "%s → %s\n", res.Value, res.Section)
	fmt.Fprintln(stdout, sectionMoreLine(res))
	for _, item := range res.Items {
		fmt.Fprintln(stdout, "  "+compactItem(item))
	}
	return exitOK
}

func sectionMoreLine(res *engine.Behaviour) string {
	if res.More {
		return fmt.Sprintf("items %d-%d of %d — continue with --offset %d",
			res.Offset+1, res.Offset+res.Retrieved, res.Total, res.Offset+res.Retrieved)
	}
	if res.Offset > 0 {
		return fmt.Sprintf("items %d-%d of %d", res.Offset+1, res.Offset+res.Retrieved, res.Total)
	}
	return fmt.Sprintf("retrieved %d", res.Retrieved)
}

// compactItem renders one section entry on one line: strings verbatim,
// structures as compact JSON, both clipped — --json carries everything.
func compactItem(item any) string {
	if s, ok := item.(string); ok {
		return clip(s, 160, "…")
	}
	b, err := json.Marshal(item)
	if err != nil {
		return fmt.Sprintf("%v", item)
	}
	return clip(string(b), 160, "… (--json for the full entry)")
}
