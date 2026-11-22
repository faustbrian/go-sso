package sso

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	organization "github.com/faustbrian/go-organization"
)

func TestDiscoveryDomainAcceptsExactDNSAndPlainASCIIAddresses(t *testing.T) {
	for _, tc := range []struct {
		input, domain string
	}{
		{"example.test", "example.test"},
		{"EXAMPLE.Test.", "example.test"},
		{"sub.example.test", "sub.example.test"},
		{"user@example.test", "example.test"},
		{"First.Last+tag@EXAMPLE.Test.", "example.test"},
		{"!#$%&'*+-/=?^_`{|}~@example.test", "example.test"},
		{"user/name@example.test", "example.test"},
		{strings.Repeat("a", 64) + "@example.test", "example.test"},
		{"user@xn--bcher-kva.test", "xn--bcher-kva.test"},
		{"user@example.test.attacker.test", "example.test.attacker.test"},
	} {
		t.Run(tc.input, func(t *testing.T) {
			domain, err := discoveryDomain(DiscoverRequest{EmailOrDomain: tc.input})
			if err != nil || domain != tc.domain {
				t.Fatalf("domain = %q, error = %v; want %q", domain, err, tc.domain)
			}
			route, err := NewDomainRouteRequest("tenant-a", domain, "")
			if err != nil {
				t.Fatal("discovery domain did not compose with the native route request", err)
			}
			binding, err := route.Bindings()
			if err != nil || binding.Domain != tc.domain || binding.ProviderID != "" {
				t.Fatal("discovery changed the exact route domain or selected a provider", err)
			}
		})
	}
}

func TestDiscoveryDomainRejectsAmbiguousOrMalformedInputWithoutDisclosure(t *testing.T) {
	for _, input := range []string{
		"", strings.Repeat("a", 321), " example.test", "example.test ", "example.test\n",
		"https://example.test", "example.test/path", "*.example.test", ".example.test",
		"//user@example.test", "//example.test", "//user:pass@example.test",
		"example..test", "example.test..", "localhost", "127.0.0.1", "[::1]",
		"éxample.test", "user@éxample.test", "usér@example.test", "user@例.test",
		"@example.test", "user@", "user@@example.test", "user@sub@example.test",
		".user@example.test", "user.@example.test", "user..name@example.test",
		strings.Repeat("a", 65) + "@example.test",
		"Display Name <user@example.test>", "<user@example.test>", "user(comment)@example.test",
		"user@example.test(comment)", "user@example.test,other@example.test",
		"user@example.test;other@example.test", "group:user@example.test;",
		"\"user\"@example.test", "user\\name@example.test", "user name@example.test",
		"user\tname@example.test", "user\r\n@example.test", "user\x00@example.test",
		"user\x7f@example.test", "user@ example.test", "user@example.test/path",
		"user@example.test?query", "user@example.test#fragment", "mailto:user@example.test",
		"user@[127.0.0.1]", "user@127.0.0.1", "user@*.example.test",
		"user\xff@example.test",
	} {
		t.Run(fmt.Sprintf("%q", input), func(t *testing.T) {
			domain, err := discoveryDomain(DiscoverRequest{EmailOrDomain: input})
			if domain != "" || !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("malformed input returned domain %q, error %v", domain, err)
			}
			if err.Error() != ErrInvalidInput.Error() {
				t.Fatal("invalid-input error disclosed request material")
			}
		})
	}
}

func TestDiscoveryDomainPreservesOwnerDNSBounds(t *testing.T) {
	longDomain := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	for _, input := range []string{longDomain, longDomain + ".", "user@" + longDomain, strings.Repeat("u", 64) + "@" + longDomain + "."} {
		domain, err := discoveryDomain(DiscoverRequest{EmailOrDomain: input})
		if err != nil || domain != longDomain {
			t.Fatalf("owner-supported maximum domain rejected: %v", err)
		}
	}
	for _, input := range []string{longDomain + "a", "user@" + longDomain + "a", strings.Repeat("a", 64) + ".test"} {
		if _, err := discoveryDomain(DiscoverRequest{EmailOrDomain: input}); !errors.Is(err, ErrInvalidInput) {
			t.Fatal("owner-rejected DNS bound accepted")
		}
	}
}

func TestDiscoverRequestRedactsFormattingAndPreservesExplicitJSONInput(t *testing.T) {
	request := DiscoverRequest{EmailOrDomain: "private.local+tag@example.test"}
	for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x"} {
		if got := fmt.Sprintf(format, request); got != "sso.DiscoverRequest(redacted)" {
			t.Fatalf("request formatting is not redacted for %s", format)
		}
	}
	wire, err := json.Marshal(request)
	if err != nil || string(wire) != `{"EmailOrDomain":"private.local+tag@example.test"}` {
		t.Fatalf("explicit discovery input JSON = %s, error = %v", wire, err)
	}
}

func TestDiscoverResultJSONContainsOnlySafeProviderChoice(t *testing.T) {
	for _, tc := range []struct {
		result DiscoverResult
		wire   string
	}{
		{DiscoverResult{}, `{"Matched":false,"RequiresConfirmation":false}`},
		{DiscoverResult{Matched: true, ProviderID: "provider-a", Protocol: "oidc"}, `{"Matched":true,"ProviderID":"provider-a","Protocol":"oidc","RequiresConfirmation":false}`},
		{DiscoverResult{Matched: true, ProviderID: "provider-a", Protocol: "oidc", RequiresConfirmation: true}, `{"Matched":true,"ProviderID":"provider-a","Protocol":"oidc","RequiresConfirmation":true}`},
	} {
		wire, err := json.Marshal(tc.result)
		if err != nil || string(wire) != tc.wire {
			t.Fatalf("public discovery result JSON = %s, error = %v; want %s", wire, err, tc.wire)
		}
	}
}

func FuzzDiscoveryDomain(f *testing.F) {
	for _, input := range []string{"example.test", "First.Last+tag@EXAMPLE.Test.", "user@example.test.attacker.test", "@example.test", "user..name@example.test", "\"user\"@example.test", "user@例.test", strings.Repeat("a", 321)} {
		f.Add(input)
	}
	f.Fuzz(func(t *testing.T, input string) {
		domain, err := discoveryDomain(DiscoverRequest{EmailOrDomain: input})
		if err != nil {
			if domain != "" || !errors.Is(err, ErrInvalidInput) || err.Error() != ErrInvalidInput.Error() {
				t.Fatal("invalid input returned a domain or nonredacted error")
			}
			return
		}
		if len(input) == 0 || len(input) > 320 {
			t.Fatal("accepted out-of-bound discovery input")
		}
		exactDomain := input
		if at := strings.IndexByte(input, '@'); at >= 0 {
			if at == 0 || at > 64 || strings.Count(input, "@") != 1 {
				t.Fatal("accepted malformed address boundary")
			}
			exactDomain = input[at+1:]
		}
		canonical, err := organization.CanonicalDomain(exactDomain)
		if err != nil || domain != canonical {
			t.Fatal("discovery did not preserve the exact owner-canonical domain")
		}
		if _, err := discoveryDomain(DiscoverRequest{EmailOrDomain: " " + input}); !errors.Is(err, ErrInvalidInput) {
			t.Fatal("discovery trimmed caller input")
		}
	})
}
