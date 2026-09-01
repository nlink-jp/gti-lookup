// Package config resolves settings from, in decreasing precedence: command
// line flags, environment variables, the config file, and built-in defaults.
//
// The file is the sectioned-TOML subset used across the series
// ([api], [query], [cache], [network]), read from
// $XDG_CONFIG_HOME/gti-lookup/config.toml and ~/.config/gti-lookup/config.toml.
//
// The API key is a secret and, unlike the sibling lookup tools, it is
// mandatory: GTI answers nothing anonymously. It is read from
// GTI_LOOKUP_API_KEY or VT_APIKEY (the variable Google's own GTI tooling
// conventionally uses, accepted so an existing environment works unchanged),
// or from [api] key. It is sent only in the x-apikey header — never in a URL,
// never logged.
package config
