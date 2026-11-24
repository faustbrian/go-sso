package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

func TestSAMLLogoutSubjectReadRestoresOriginalRowAfterKeyRotation(t *testing.T) {
	payload, _, now, _ := providerLoginPayloadFixture(t)
	for _, index := range []string{"", "original-session-index"} {
		t.Run("index="+index, func(t *testing.T) {
			custody, row, original := samlLogoutSubjectReadFixture(t, payload, *now, index)
			custody.config.CurrentMatchKey = 2
			anchor, scope, subject, err := custody.openRow(t.Context(), payload.Envelope, identity.TenantID(row.anchor.Tenant), row.anchor.Session, row)
			if err != nil || anchor != row.anchor || scope.organization != row.anchor.Organization || scope.provider != row.anchor.Provider || scope.issuer != "urn:example:original-idp" || subject != original {
				t.Fatal("reader did not preserve exact original row and signed subject", err)
			}
		})
	}
}

func TestSAMLLogoutSubjectReadReconstructsOriginalUTCAnchor(t *testing.T) {
	payload, _, now, _ := providerLoginPayloadFixture(t)
	custody, row, original := samlLogoutSubjectReadFixture(t, payload, *now, "")
	want := row.anchor
	zone := time.FixedZone("database-session-zone", 2*60*60)
	row.anchor.Command = ""
	row.anchor.IssuedAt = row.anchor.IssuedAt.In(zone)
	row.anchor.ExpiresAt = row.anchor.ExpiresAt.In(zone)
	anchor, _, subject, err := custody.openRow(t.Context(), payload.Envelope, identity.TenantID(row.anchor.Tenant), row.anchor.Session, row)
	if err != nil || anchor != want || subject != original {
		t.Fatal("database representation did not reconstruct exact authenticated anchor", err)
	}
}

func TestSAMLLogoutSubjectReadRequiresTheEnvelopeKeyAndLiveContext(t *testing.T) {
	payload, _, now, _ := providerLoginPayloadFixture(t)
	custody, row, _ := samlLogoutSubjectReadFixture(t, payload, *now, "")
	keys, err := keyring.New(map[string][]byte{"other-key": bytes.Repeat([]byte{3}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := envelope.NewService(keys)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for _, test := range []struct {
		name   string
		ctx    context.Context
		crypto *envelope.Service
	}{
		{"unknown envelope key", t.Context(), foreign},
		{"cancelled", ctx, payload.Envelope},
		{"nil context", nil, payload.Envelope},
		{"nil envelope service", t.Context(), nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			anchor, scope, subject, err := custody.openRow(test.ctx, test.crypto, identity.TenantID(row.anchor.Tenant), row.anchor.Session, row)
			if err == nil || anchor != (samlLogoutIssuanceAnchor{}) || scope != (samlLogoutIssuerScope{}) || subject != (samlStoredLogoutSubject{}) {
				t.Fatal("failed decryption or context released custody")
			}
		})
	}
	anchor, scope, subject, found, err := custody.read(t.Context(), nil, payload.Envelope, identity.TenantID(row.anchor.Tenant), row.anchor.Session)
	if err == nil || found || anchor != (samlLogoutIssuanceAnchor{}) || scope != (samlLogoutIssuerScope{}) || subject != (samlStoredLogoutSubject{}) {
		t.Fatal("missing database released custody")
	}
}

func TestSAMLLogoutSubjectReadRejectsInvalidValuesEvenWithMatchingDigest(t *testing.T) {
	payload, _, now, _ := providerLoginPayloadFixture(t)
	for _, test := range []struct {
		name string
		edit func(*samlLogoutIssuerScope, *samlStoredLogoutSubject)
	}{
		{"empty subject", func(_ *samlLogoutIssuerScope, s *samlStoredLogoutSubject) { s.ProviderSubject = "" }},
		{"blank subject", func(_ *samlLogoutIssuerScope, s *samlStoredLogoutSubject) { s.ProviderSubject = "  " }},
		{"unsupported format", func(_ *samlLogoutIssuerScope, s *samlStoredLogoutSubject) { s.SubjectFormat = "urn:unsupported" }},
		{"invalid index", func(_ *samlLogoutIssuerScope, s *samlStoredLogoutSubject) { s.SessionIndex = "bad\x00index" }},
		{"different qualifier", func(_ *samlLogoutIssuerScope, s *samlStoredLogoutSubject) { s.NameQualifier = "urn:different:idp" }},
		{"invalid SP qualifier", func(_ *samlLogoutIssuerScope, s *samlStoredLogoutSubject) { s.SPNameQualifier = "bad\uffffqualifier" }},
		{"blank issuer", func(scope *samlLogoutIssuerScope, s *samlStoredLogoutSubject) {
			scope.issuer = " "
			s.NameQualifier = ""
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			custody, row, subject := samlLogoutSubjectReadFixture(t, payload, *now, "")
			scope := samlLogoutIssuerScope{row.anchor.Organization, row.anchor.Provider, "urn:example:original-idp"}
			test.edit(&scope, &subject)
			prepared, err := custody.prepare(t.Context(), payload.Envelope, row.anchor, scope, &subject)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(prepared.Envelope)
			row.wire = prepared.Envelope
			row.subjectDigest = prepared.Subject[:]
			if prepared.Index != nil {
				row.indexDigest = prepared.Index[:]
			}
			_, _, released, err := custody.openRow(t.Context(), payload.Envelope, identity.TenantID(row.anchor.Tenant), row.anchor.Session, row)
			if err == nil || released != (samlStoredLogoutSubject{}) {
				t.Fatal("matching authenticated custody bypassed scalar validation")
			}
		})
	}
}

func TestSAMLLogoutSubjectReadRejectsForeignOrCorruptCustody(t *testing.T) {
	payload, _, now, _ := providerLoginPayloadFixture(t)
	for _, test := range []struct {
		name string
		edit func(*SAMLLogoutSubjectCustody, *samlLogoutSubjectRow, *identity.TenantID, *string)
	}{
		{"foreign tenant", func(_ *SAMLLogoutSubjectCustody, _ *samlLogoutSubjectRow, tenant *identity.TenantID, _ *string) {
			*tenant = "other-tenant"
		}},
		{"foreign session", func(_ *SAMLLogoutSubjectCustody, _ *samlLogoutSubjectRow, _ *identity.TenantID, session *string) {
			*session = "other-session"
		}},
		{"foreign row binding", func(_ *SAMLLogoutSubjectCustody, r *samlLogoutSubjectRow, _ *identity.TenantID, _ *string) {
			r.anchor.Family = "other-family"
		}},
		{"changed provider", func(_ *SAMLLogoutSubjectCustody, r *samlLogoutSubjectRow, _ *identity.TenantID, _ *string) {
			r.anchor.Provider = "other-provider"
		}},
		{"changed command", func(_ *SAMLLogoutSubjectCustody, r *samlLogoutSubjectRow, _ *identity.TenantID, _ *string) {
			r.command[0] ^= 1
		}},
		{"invalid command", func(_ *SAMLLogoutSubjectCustody, r *samlLogoutSubjectRow, _ *identity.TenantID, _ *string) {
			r.command = r.command[:15]
		}},
		{"unexpected purpose", func(_ *SAMLLogoutSubjectCustody, r *samlLogoutSubjectRow, _ *identity.TenantID, _ *string) {
			r.anchor.Purpose = "identity.sso.oauth-callback"
		}},
		{"invalid lifetime", func(_ *SAMLLogoutSubjectCustody, r *samlLogoutSubjectRow, _ *identity.TenantID, _ *string) {
			r.anchor.ExpiresAt = r.anchor.IssuedAt
		}},
		{"invalid time precision", func(_ *SAMLLogoutSubjectCustody, r *samlLogoutSubjectRow, _ *identity.TenantID, _ *string) {
			r.anchor.IssuedAt = r.anchor.IssuedAt.Add(time.Nanosecond)
		}},
		{"noncanonical organization", func(_ *SAMLLogoutSubjectCustody, r *samlLogoutSubjectRow, _ *identity.TenantID, _ *string) {
			r.anchor.Organization = " padded"
		}},
		{"unknown retained key", func(c *SAMLLogoutSubjectCustody, _ *samlLogoutSubjectRow, _ *identity.TenantID, _ *string) {
			delete(c.config.MatchKeys, 1)
		}},
		{"zero key version", func(_ *SAMLLogoutSubjectCustody, r *samlLogoutSubjectRow, _ *identity.TenantID, _ *string) {
			r.keyVersion = 0
		}},
		{"overflow key version", func(_ *SAMLLogoutSubjectCustody, r *samlLogoutSubjectRow, _ *identity.TenantID, _ *string) {
			r.keyVersion = 1 << 32
		}},
		{"short digest", func(_ *SAMLLogoutSubjectCustody, r *samlLogoutSubjectRow, _ *identity.TenantID, _ *string) {
			r.subjectDigest = r.subjectDigest[:31]
		}},
		{"changed digest", func(_ *SAMLLogoutSubjectCustody, r *samlLogoutSubjectRow, _ *identity.TenantID, _ *string) {
			r.subjectDigest[0] ^= 1
		}},
		{"short index", func(_ *SAMLLogoutSubjectCustody, r *samlLogoutSubjectRow, _ *identity.TenantID, _ *string) {
			r.indexDigest = r.indexDigest[:31]
		}},
		{"missing index", func(_ *SAMLLogoutSubjectCustody, r *samlLogoutSubjectRow, _ *identity.TenantID, _ *string) {
			r.indexDigest = nil
		}},
		{"corrupt envelope", func(_ *SAMLLogoutSubjectCustody, r *samlLogoutSubjectRow, _ *identity.TenantID, _ *string) {
			r.wire[len(r.wire)-1] ^= 1
		}},
		{"oversized envelope", func(_ *SAMLLogoutSubjectCustody, r *samlLogoutSubjectRow, _ *identity.TenantID, _ *string) {
			r.wire = make([]byte, samlLogoutSubjectEnvelopeLimit+1)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			custody, row, _ := samlLogoutSubjectReadFixture(t, payload, *now, "original-session-index")
			tenant, session := identity.TenantID(row.anchor.Tenant), row.anchor.Session
			test.edit(custody, &row, &tenant, &session)
			anchor, scope, subject, err := custody.openRow(t.Context(), payload.Envelope, tenant, session, row)
			if err == nil || anchor != (samlLogoutIssuanceAnchor{}) || scope != (samlLogoutIssuerScope{}) || subject != (samlStoredLogoutSubject{}) {
				t.Fatal("invalid custody released original subject or binding")
			}
		})
	}
}

func TestSAMLLogoutSubjectReadStrictlyValidatesAuthenticatedPayload(t *testing.T) {
	payload, _, now, _ := providerLoginPayloadFixture(t)
	for _, test := range []struct {
		name string
		edit func([]byte) []byte
	}{
		{"unknown field", func(p []byte) []byte {
			return bytes.Replace(p, []byte(`{"Issuer"`), []byte(`{"Unexpected":true,"Issuer"`), 1)
		}},
		{"duplicate issuer", func(p []byte) []byte {
			return bytes.Replace(p, []byte(`{"Issuer"`), []byte(`{"Issuer":"urn:foreign:idp","Issuer"`), 1)
		}},
		{"foreign issuer", func(p []byte) []byte {
			return bytes.ReplaceAll(p, []byte("urn:example:original-idp"), []byte("urn:foreign:idp"))
		}},
		{"different signed subject", func(p []byte) []byte {
			return bytes.Replace(p, []byte("original-subject"), []byte("different-subject"), 1)
		}},
		{"invalid NameID format", func(p []byte) []byte {
			return bytes.Replace(p, []byte("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"), []byte("urn:unsupported"), 1)
		}},
		{"invalid subject text", func(p []byte) []byte {
			return bytes.Replace(p, []byte("original-subject"), []byte(`bad\u0000subject`), 1)
		}},
		{"second JSON value", func(p []byte) []byte { return append(p, []byte("{}")...) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			custody, row, original := samlLogoutSubjectReadFixture(t, payload, *now, "original-session-index")
			prepared := samlPreparedLogoutSubject{KeyVersion: 1}
			copy(prepared.Subject[:], row.subjectDigest)
			prepared.Index = new([32]byte)
			copy(prepared.Index[:], row.indexDigest)
			aad, err := samlLogoutSubjectAAD(row.anchor, prepared)
			if err != nil {
				t.Fatal(err)
			}
			plain, err := providerLoginPayloadEncode(struct {
				Issuer  string
				Subject samlStoredLogoutSubject
			}{"urn:example:original-idp", original})
			if err != nil {
				t.Fatal(err)
			}
			defer clear(plain)
			changed := test.edit(plain)
			defer clear(changed)
			row.wire, err = payload.seal(t.Context(), aad, changed, samlLogoutSubjectEnvelopeLimit)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(row.wire)
			_, _, subject, err := custody.openRow(t.Context(), payload.Envelope, identity.TenantID(row.anchor.Tenant), row.anchor.Session, row)
			if err == nil || subject != (samlStoredLogoutSubject{}) {
				t.Fatal("authenticated invalid payload released a subject")
			}
		})
	}
}

func samlLogoutSubjectReadFixture(t *testing.T, payload providerLoginPayloadConfig, now time.Time, index string) (*SAMLLogoutSubjectCustody, samlLogoutSubjectRow, samlStoredLogoutSubject) {
	t.Helper()
	command := bytes.Repeat([]byte{0x41}, 16)
	anchor := samlLogoutIssuanceAnchor{Tenant: "tenant", Organization: "organization", Provider: "provider", User: "user", Session: "session", Family: "family", Purpose: "identity.sso.saml-acs", Command: base64.RawURLEncoding.EncodeToString(command), IssuedAt: now.Add(123456 * time.Microsecond), ExpiresAt: now.Add(time.Hour)}
	scope := samlLogoutIssuerScope{anchor.Organization, anchor.Provider, "urn:example:original-idp"}
	subject := samlStoredLogoutSubject{ProviderSubject: "original-subject", SubjectFormat: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent", NameQualifier: scope.issuer, SPNameQualifier: "https://app.example/sp", SessionIndex: index}
	custody, err := NewSAMLLogoutSubjectCustody(SAMLLogoutSubjectCustodyConfig{KeyReference: payload.KeyReference, CurrentMatchKey: 1, MatchKeys: map[uint32][32]byte{1: {0x19}, 2: {0x29}}})
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := custody.prepare(t.Context(), payload.Envelope, anchor, scope, &subject)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(prepared.Envelope) })
	row := samlLogoutSubjectRow{anchor: anchor, command: command, keyVersion: int64(prepared.KeyVersion), subjectDigest: bytes.Clone(prepared.Subject[:]), wire: bytes.Clone(prepared.Envelope)}
	if prepared.Index != nil {
		row.indexDigest = bytes.Clone(prepared.Index[:])
	}
	t.Cleanup(func() { clear(row.wire) })
	return custody, row, subject
}
