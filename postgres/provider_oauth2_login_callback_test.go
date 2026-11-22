package postgres

import (
	"net/url"
	"strings"
	"testing"
)

func FuzzProviderOAuth2CallbackStateLocator(f *testing.F) {
	f.Add("https://provider.example/Enterprise")
	f.Add("%ZZ&st%61te=other")
	f.Add("\x00?£")
	const maxIssuer = 2048
	state := strings.Repeat("A", 43)
	f.Fuzz(func(t *testing.T, issuer string) {
		if len(issuer) > maxIssuer {
			return
		}
		// This owner only locates state. Unknown or invalid issuer contents
		// are later verified by the trusted shared parser, not by lookup.
		raw := "state=" + state + "&iss=" + url.QueryEscape(issuer)
		if got, err := providerOAuth2CallbackState(raw); err != nil || got != state {
			t.Fatal("issuer bytes influenced original state selection")
		}
		if got, err := providerOAuth2CallbackState(raw + "&st%61te=" + state); err == nil || got != "" {
			t.Fatal("escaped duplicate state was accepted as a lookup hint")
		}
	})
}
