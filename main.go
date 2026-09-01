// Command gti-lookup attaches curated threat-actor context to an indicator or
// a search term by reading Google Threat Intelligence (GTI), as a CLI and a
// local MCP server. Where otx-lookup answers from community reports, this one
// answers from the Mandiant/Google curated catalogue: which threat actor,
// campaign or malware family an indicator is associated with, who that actor
// targets, and which reports describe it — in both directions, actor → IOCs
// and IOC → actor.
//
// Only Google's index is read, so no packet reaches the target under
// investigation. A valid GTI licence is required: the API key is mandatory,
// and every query is recorded against the licence holder's account.
//
// The tool is read-only by design: no collection writes and no sample
// uploads, permanently.
package main

import (
	"os"

	"github.com/nlink-jp/gti-lookup/internal/app"
)

// version is set at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	os.Exit(app.Run(os.Args[1:], version))
}
