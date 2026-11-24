package saml_test

import (
	"strings"
	"testing"

	"github.com/faustbrian/go-sso/saml"
)

func TestLocalRevocationValidOutcomesRemainDistinct(t *testing.T) {
	outcomes := map[saml.LocalRevocation]string{
		{SessionID: "local-session", Version: 1, Committed: true}:              "committed",
		{SessionID: "local-session", Version: 1}:                               "not committed",
		{SessionID: "local-session", Version: 1, ReconciliationRequired: true}: "unknown",
	}
	if len(outcomes) != 3 {
		t.Fatal("local revocation outcomes collapsed")
	}
	for outcome, name := range outcomes {
		t.Run(name, func(t *testing.T) {
			original := outcome
			if err := outcome.Validate(); err != nil {
				t.Fatalf("valid outcome rejected: %v", err)
			}
			if outcome != original {
				t.Fatal("validation changed the local revocation projection")
			}
		})
	}
}

func TestLocalRevocationAcceptsIdentitySessionBoundaries(t *testing.T) {
	for _, id := range []string{"!", "~", "session_1-.:/", strings.Repeat("s", 128)} {
		t.Run(id, func(t *testing.T) {
			outcome := saml.LocalRevocation{SessionID: id, Version: ^uint64(0), Committed: true}
			if err := outcome.Validate(); err != nil {
				t.Fatalf("canonical Identity session rejected: %v", err)
			}
		})
	}
	for b := byte(33); b <= 126; b++ {
		outcome := saml.LocalRevocation{SessionID: string([]byte{b}), Version: 1}
		if err := outcome.Validate(); err != nil {
			t.Fatalf("visible ASCII byte %d rejected: %v", b, err)
		}
	}
}

func TestLocalRevocationRejectsInvalidStateWithoutExposingIdentity(t *testing.T) {
	tests := []struct {
		name    string
		outcome saml.LocalRevocation
	}{
		{"zero", saml.LocalRevocation{}},
		{"missing session", saml.LocalRevocation{Version: 1}},
		{"missing version", saml.LocalRevocation{SessionID: "local-session"}},
		{"committed cannot require reconciliation", saml.LocalRevocation{SessionID: "local-session", Version: 1, Committed: true, ReconciliationRequired: true}},
		{"oversized session", saml.LocalRevocation{SessionID: strings.Repeat("s", 129), Version: 1}},
		{"leading space", saml.LocalRevocation{SessionID: " sensitive-session", Version: 1}},
		{"trailing space", saml.LocalRevocation{SessionID: "sensitive-session ", Version: 1}},
		{"embedded space", saml.LocalRevocation{SessionID: "sensitive session", Version: 1}},
		{"unicode session", saml.LocalRevocation{SessionID: "sessiön", Version: 1}},
		{"invalid UTF-8", saml.LocalRevocation{SessionID: "session\xff", Version: 1}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			original := tt.outcome
			if err := tt.outcome.Validate(); err != saml.ErrInvalidInput {
				t.Fatalf("invalid state must return only ErrInvalidInput, got %v", err)
			}
			if tt.outcome != original {
				t.Fatal("invalid projection was normalized or otherwise changed")
			}
		})
	}
	for b := 0; b <= 255; b++ {
		if b >= 33 && b <= 126 {
			continue
		}
		outcome := saml.LocalRevocation{SessionID: "session" + string([]byte{byte(b)}), Version: 1}
		if err := outcome.Validate(); err != saml.ErrInvalidInput {
			t.Fatalf("noncanonical Identity byte %d accepted: %v", b, err)
		}
	}
}
