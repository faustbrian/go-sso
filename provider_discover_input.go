package sso

import (
	"fmt"
	"strings"

	organization "github.com/faustbrian/go-organization"
)

// DiscoverRequest borrows 1..320 bytes of an exact ASCII DNS name or a plain
// ASCII email address. Addresses use a 1..64-byte unquoted dot-atom local part;
// only the domain is used for discovery, never an account lookup. DNS handling
// follows organization.CanonicalDomain without trimming or implicit IDNA.
// Formatting is redacted; explicit JSON serialization contains the input.
type DiscoverRequest struct {
	EmailOrDomain string
}

func (DiscoverRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("sso.DiscoverRequest(redacted)"))
}

// DiscoverResult is a safe provider choice, not organization metadata, native
// routing evidence, authentication or login authority. The zero value is a
// valid no-match result: ProviderID and Protocol are absent and confirmation is
// false. A match includes the selected provider ID (1..128 bytes) and protocol
// (1..8 bytes); confirmation may be required only for a match.
type DiscoverResult struct {
	Matched              bool
	ProviderID           string `json:",omitempty"`
	Protocol             string `json:",omitempty"`
	RequiresConfirmation bool
}

func discoveryDomain(request DiscoverRequest) (string, error) {
	input := request.EmailOrDomain
	if len(input) == 0 || len(input) > 320 {
		return "", ErrInvalidInput
	}
	// A network-path URL can resemble an address with slash in its local
	// part. Discovery accepts literal addresses, not URL selectors.
	if strings.HasPrefix(input, "//") {
		return "", ErrInvalidInput
	}

	domain := input
	if local, addressDomain, address := strings.Cut(input, "@"); address {
		if !plainDiscoveryLocalPart(local) {
			return "", ErrInvalidInput
		}
		// The discovery contract selects only the exact domain. Local-part
		// validation must precede discarding it; permissive mailbox parsing
		// would admit display names, comments or other nonliteral selectors.
		domain = addressDomain
	}
	canonical, err := organization.CanonicalDomain(domain)
	if err != nil {
		return "", ErrInvalidInput
	}
	return canonical, nil
}

func plainDiscoveryLocalPart(local string) bool {
	if len(local) == 0 || len(local) > 64 || local[0] == '.' || local[len(local)-1] == '.' || strings.Contains(local, "..") {
		return false
	}
	for i := 0; i < len(local); i++ {
		b := local[i]
		if b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' {
			continue
		}
		switch b {
		case '.', '!', '#', '$', '%', '&', '\'', '*', '+', '-', '/', '=', '?', '^', '_', '`', '{', '|', '}', '~':
			continue
		default:
			return false
		}
	}
	return true
}
