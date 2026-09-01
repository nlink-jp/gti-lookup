package app

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strings"
)

// runHunting lists the account's LiveHunt rulesets, or shows one by id. Both
// answer live (never from the cache): this is the command that answers "did
// my rule take?".
func runHunting(args []string, version string, stdout, stderr io.Writer) int {
	var common commonFlags
	fs := flag.NewFlagSet("hunting", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { usage(stderr) }
	common.register(fs)

	positional, err := parseInterleaved(fs, args)
	if err != nil {
		return exitError
	}
	if len(positional) > 1 {
		fmt.Fprintln(stderr, "gti-lookup: hunting takes at most one ruleset id")
		return exitError
	}

	eng, err := common.buildEngine(version)
	if err != nil {
		return fail(stderr, err)
	}
	ctx := context.Background()

	if len(positional) == 0 {
		res, err := eng.HuntingRulesets(ctx, common.limit)
		if err != nil {
			return fail(stderr, err)
		}
		if common.jsonOut {
			if err := renderJSON(stdout, res); err != nil {
				return fail(stderr, err)
			}
			return exitOK
		}
		fmt.Fprintf(stdout, "LiveHunt rulesets: %s\n", moreLine(res.Retrieved, res.More, 0))
		for _, r := range res.Items {
			fmt.Fprintf(stdout, "  %-14s %-9s %2d rule(s)  %s\n", r.ID, enabledWord(r.Enabled), r.NumberOfRules, orDash(r.Name))
		}
		if res.Retrieved == 0 {
			fmt.Fprintln(stdout, "no rulesets on this account — create them in the GTI console (LiveHunt)")
		}
		return exitOK
	}

	res, err := eng.HuntingRuleset(ctx, positional[0])
	if err != nil {
		return fail(stderr, err)
	}
	if common.jsonOut {
		if err := renderJSON(stdout, res); err != nil {
			return fail(stderr, err)
		}
		return exitOK
	}
	fmt.Fprintf(stdout, "ruleset %s: %s\n", res.ID, orDash(res.Name))
	fmt.Fprintf(stdout, "  enabled: %t", res.Enabled)
	if !res.Enabled {
		fmt.Fprint(stdout, "  (LiveHunt will not fire — enable it in the GTI console)")
	}
	fmt.Fprintln(stdout)
	if res.MatchObjectType != "" {
		fmt.Fprintf(stdout, "  matches: %s\n", res.MatchObjectType)
	}
	if len(res.RuleNames) > 0 {
		fmt.Fprintf(stdout, "  rules (%d): %s\n", res.NumberOfRules, strings.Join(res.RuleNames, ", "))
	}
	if res.CreationDate != "" {
		fmt.Fprintf(stdout, "  created %s  modified %s\n", res.CreationDate, orDash(res.Modified))
	}
	if res.Rules != "" {
		fmt.Fprintln(stdout)
		fmt.Fprintln(stdout, res.Rules)
	}
	return exitOK
}

func enabledWord(enabled bool) string {
	if enabled {
		return "enabled"
	}
	return "disabled"
}
