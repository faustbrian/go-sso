package postgres

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-sso"
)

func TestSAMLLogoutSubjectCustodyRedactsPointerAndValue(t *testing.T) {
	const reference = "fixture-private-reference"
	custody, err := NewSAMLLogoutSubjectCustody(SAMLLogoutSubjectCustodyConfig{
		KeyReference: reference, CurrentMatchKey: 1, MatchKeys: map[uint32][32]byte{1: {0xa2}},
	})
	if err != nil {
		t.Fatal("select custody", err)
	}
	for _, shape := range []struct {
		name  string
		value any
	}{{"pointer", custody}, {"value", *custody}} {
		t.Run(shape.name, func(t *testing.T) {
			if got := fmt.Sprintf("%#v", shape.value); !strings.Contains(got, "redacted") || strings.Contains(got, reference) {
				t.Fatal("custody diagnostics disclosed configuration")
			}
			if out, err := json.Marshal(shape.value); len(out) != 0 || !errors.Is(err, sso.ErrSensitiveSerialization) {
				t.Fatal("custody has no public serialization", err)
			}
		})
	}
}

func TestSAMLLogoutSubjectCustodyRestoresExactSignedSubjectWithRetainedKey(t *testing.T) {
	payload, _, now, _ := providerLoginPayloadFixture(t)
	scope := samlLogoutIssuerScope{organization: "fixture-org", provider: "fixture-provider", issuer: "https://idp.example.test"}
	anchor := samlLogoutIssuanceAnchor{Tenant: "fixture-tenant", Organization: scope.organization, Provider: scope.provider,
		User: "fixture-user", Session: "fixture-session", Family: "fixture-family", Purpose: "identity.sso.saml-acs",
		Command: "fixture-command", IssuedAt: *now, ExpiresAt: now.Add(time.Hour)}
	subject := samlStoredLogoutSubject{ProviderSubject: "original-signed-name-id", SubjectFormat: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
		NameQualifier: "original-idp-qualifier", SPNameQualifier: "original-sp-qualifier", SessionIndex: "original-index"}
	keys := map[uint32][32]byte{1: {0x19}, 2: {0x29}}
	original, err := NewSAMLLogoutSubjectCustody(SAMLLogoutSubjectCustodyConfig{KeyReference: payload.KeyReference, CurrentMatchKey: 1, MatchKeys: keys})
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := original.prepare(t.Context(), payload.Envelope, anchor, scope, &subject)
	if err != nil || prepared.KeyVersion != 1 {
		t.Fatal("prepare subject with the original active key", err)
	}
	defer clear(prepared.Envelope)
	rotated, err := NewSAMLLogoutSubjectCustody(SAMLLogoutSubjectCustodyConfig{KeyReference: payload.KeyReference, CurrentMatchKey: 2, MatchKeys: keys})
	if err != nil {
		t.Fatal(err)
	}
	delete(keys, 1)
	if err := rotated.validatePrepared(prepared, anchor, scope, &subject); err != nil {
		t.Fatal("rotation discarded the retained original match key", err)
	}
	changed := subject
	changed.SPNameQualifier = "changed-sp-qualifier"
	if err := rotated.validatePrepared(prepared, anchor, scope, &changed); err == nil {
		t.Fatal("prepared match accepted a different signed qualifier")
	}

	aad, err := samlLogoutSubjectAAD(anchor, *prepared)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := payload.open(t.Context(), aad, prepared.Envelope, samlLogoutSubjectEnvelopeLimit, providerLoginCallbackPlainLimit)
	defer clear(wire)
	var restored struct {
		Issuer  string
		Subject samlStoredLogoutSubject
	}
	if err != nil || json.Unmarshal(wire, &restored) != nil || restored.Issuer != scope.issuer || restored.Subject != subject {
		t.Fatal("sealed custody discarded the exact signed subject or issuer", err)
	}
	anchor.Session = "foreign-session"
	foreignAAD, err := samlLogoutSubjectAAD(anchor, *prepared)
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := payload.open(t.Context(), foreignAAD, prepared.Envelope, samlLogoutSubjectEnvelopeLimit, providerLoginCallbackPlainLimit)
	defer clear(foreign)
	if err == nil || len(foreign) != 0 {
		t.Fatal("sealed custody could be opened for a foreign session")
	}
}
