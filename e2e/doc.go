// Package e2e holds live tests against the real GTI API, behind the `e2e`
// build tag (network and a licensed key required; run via `make e2e`; the
// suite skips itself when no key is configured). Assertions are behavioural,
// never exact counts. Live measurements that contradict the documented API
// behaviour are recorded in AGENTS.md under Gotchas.
package e2e
