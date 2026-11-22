package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	authentication "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
)

// The independent wire fixture lets the existing implementation reject the
// authenticated profile at runtime before its private storage type is added.
type providerLoginLinkTestIntent struct {
	OriginalSession                                        []identity.FeatureField
	ConsentedAt                                            time.Time
	OrganizationVersion, OrganizationCredentialVersion     uint64
	MembershipVersion, AuthorizationVersion, FactorVersion uint64
}

func providerLoginLinkTestSession(t *testing.T, now time.Time, mutate func(*session.SessionSpec)) session.Session {
	t.Helper()
	policy, err := session.NewRememberPolicy(session.RememberPolicySpec{Choice: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: time.Hour, RefreshAfter: time.Minute, FreshFor: 15 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	vector := session.AuthoritySnapshotSpec{}
	for n, binding := range []*session.AuthorityBinding{&vector.Global, &vector.Tenant, &vector.User, &vector.Identifier, &vector.Credential, &vector.SessionFamily, &vector.Session, &vector.Authorization} {
		*binding = session.AuthorityBinding{ScopeKey: fmt.Sprintf("dimension-%d", n), Version: uint64(n + 1)}
	}
	authority, err := session.NewAuthoritySnapshot(vector)
	if err != nil {
		t.Fatal(err)
	}
	spec := session.SessionSpec{SessionID: "local-session", FamilyID: "local-family", TenantID: "tenant", UserID: "member", Audience: "identity", Version: vector.Session.Version, FamilyVersion: vector.SessionFamily.Version, Remember: policy, Authority: authority, Lookup: session.TokenDigest{KeyVersion: 1, Sum: [32]byte{41}}, Authentication: session.AuthenticationMetadata{Kind: session.AuthenticationVerified, Proof: authentication.Proof{ID: "AwMDAwMDAwMDAwMDAwMDAw", Tenant: "tenant", Subject: "member", Method: "password", Assurance: authentication.AssuranceSingleFactor, Purpose: "session-issue", Audience: "identity", IssuedAt: now.Add(-10 * time.Minute), ExpiresAt: now.Add(-9 * time.Minute)}, ProofVersion: 2, CredentialID: "local-password", CredentialVersion: 3}, IssuedAt: now.Add(-9 * time.Minute), LastActivityAt: now.Add(-time.Minute)}
	if mutate != nil {
		mutate(&spec)
	}
	csrf, err := session.NewCSRFState(session.CSRFStateSpec{Binding: session.CSRFBinding{TenantID: spec.TenantID, SessionID: spec.SessionID, SessionVersion: spec.Version}, KeyVersion: 2, Digest: [32]byte{42}})
	if err != nil {
		t.Fatal(err)
	}
	original, err := session.NewSessionWithCSRF(spec, csrf)
	if err != nil {
		t.Fatal(err)
	}
	return original
}

func providerLoginLinkTestInput(t *testing.T, anonymous providerLoginPayloadInput, original session.Session, mutate func(*providerLoginLinkTestIntent)) providerLoginPayloadInput {
	t.Helper()
	fields, err := sessionpg.OriginalSessionFields(original)
	if err != nil {
		t.Fatal(err)
	}
	intent := providerLoginLinkTestIntent{OriginalSession: fields, ConsentedAt: anonymous.IssuedAt, OrganizationVersion: 11, OrganizationCredentialVersion: 12, MembershipVersion: 13, AuthorizationVersion: 14, FactorVersion: 15}
	if mutate != nil {
		mutate(&intent)
	}
	anonymous.Command.AnonymousFlowID = ""
	anonymous.Command.UserID = "member"
	anonymous.Command.ActorID = "member"
	anonymous.Command.ActorKind = authorization.SubjectUser
	anonymous.Command.SchemaID = "identity.sso.signin-start.oidc-link-v1"
	anonymous.ExpiresAt = anonymous.IssuedAt.Add(5 * time.Minute)
	wire, err := providerLoginPayloadEncode(struct {
		providerLoginPayloadInput
		Link *providerLoginLinkTestIntent
	}{providerLoginPayloadInput: anonymous, Link: &intent})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(wire)
	var input providerLoginPayloadInput
	if err := json.Unmarshal(wire, &input); err != nil {
		t.Fatal(err)
	}
	return input
}

func TestProviderLoginLinkPayloadPreservesMemberConsentAndSignedSubject(t *testing.T) {
	c, anonymous, now, keys := providerLoginPayloadFixture(t)
	original := providerLoginLinkTestSession(t, *now, nil)
	input := providerLoginLinkTestInput(t, anonymous, original, nil)
	wire, err := c.generate(context.Background(), input, 1, risk.PreparedAuthenticationAdmission{})
	if err != nil {
		t.Fatal("explicit member consent cannot enter existing encrypted transaction", err)
	}
	out, err := c.restore(context.Background(), input, 1, wire)
	if err != nil {
		t.Fatal(err)
	}
	bindingWire, err := out.State.binding.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	stored, err := c.openCommittedBinding(context.Background(), input.rowIdentity(), bindingWire)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(stored.Proof)
	if !reflect.DeepEqual(stored.Metadata.Input, input) {
		t.Fatal("original member consent changed during encrypted recovery")
	}
	var retained struct{ Link *providerLoginLinkTestIntent }
	plain, err := providerLoginPayloadEncode(stored.Metadata.Input)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(plain)
	if json.Unmarshal(plain, &retained) != nil || retained.Link == nil || retained.Link.OrganizationVersion != 11 || retained.Link.OrganizationCredentialVersion != 12 || retained.Link.MembershipVersion != 13 || retained.Link.AuthorizationVersion != 14 || retained.Link.FactorVersion != 15 {
		t.Fatal("encrypted transaction omitted member authority epochs")
	}
	fields, err := sessionpg.OriginalSessionFields(original)
	if err != nil || !reflect.DeepEqual(retained.Link.OriginalSession, fields) {
		t.Fatal("encrypted transaction omitted original session or CSRF commitments", err)
	}
	grant, err := capability.Verify(context.Background(), string(stored.Proof), keys, capability.VerifyOptions{Issuer: c.CapabilityIssuer, Now: *now, Limits: capability.DefaultLimits()})
	if err != nil {
		t.Fatal(err)
	}
	payload := grant.Payload()
	metadata, err := providerLoginPayloadEncode(stored.Metadata)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(metadata)
	digest := sha256.Sum256(metadata)
	if payload.Subject != "member" || payload.Tenant != "tenant" || payload.Resource != input.Command.RecordID || payload.Operation != "identity.sso.oidc-callback" || payload.MaxUses != 1 || payload.Bearer || !payload.ExpiresAt.Equal(input.ExpiresAt) || payload.Caveats["identity.sso.rp.binding"] != base64.RawURLEncoding.EncodeToString(digest[:]) {
		t.Fatal("callback proof does not bind exact member and complete original consent")
	}
	if bytes.Contains(wire, []byte("local-password")) || bytes.Contains(bindingWire, []byte("local-password")) || bytes.Contains(wire, stored.Proof) {
		t.Fatal("member provenance escaped its encrypted owner")
	}
	if got := fmt.Sprintf("%#v", input.Link); got != "postgres.providerLoginMemberIntent(redacted)" {
		t.Fatal("member intent formatting disclosed correlated session data")
	}
	*now = now.Add(time.Minute)
	again, err := c.restore(context.Background(), input, 1, wire)
	if err != nil || !again.State.expiresAt.Equal(input.ExpiresAt) {
		t.Fatal("recovery renewed original consent deadline", err)
	}
	foreign := providerLoginLinkTestInput(t, anonymous, original, func(i *providerLoginLinkTestIntent) { i.MembershipVersion++ })
	if _, err := c.restore(context.Background(), foreign, 1, wire); err == nil {
		t.Fatal("recovery accepted substituted membership consent")
	}
}

func TestProviderLoginLinkPayloadRejectsWrongScopeAndUnsupportedAuthority(t *testing.T) {
	for name, mutate := range map[string]func(*providerLoginPayloadInput){
		"foreign member":      func(i *providerLoginPayloadInput) { i.Command.UserID, i.Command.ActorID = "foreign", "foreign" },
		"foreign tenant":      func(i *providerLoginPayloadInput) { i.Command.TenantID = "foreign" },
		"different actor":     func(i *providerLoginPayloadInput) { i.Command.ActorID = "other" },
		"service actor":       func(i *providerLoginPayloadInput) { i.Command.ActorKind = authorization.SubjectServiceAccount },
		"anonymous schema":    func(i *providerLoginPayloadInput) { i.Command.SchemaID = "identity.sso.signin-start.oidc-v1" },
		"record substitution": func(i *providerLoginPayloadInput) { i.Command.RecordID = "other" },
		"renewed freshness":   func(i *providerLoginPayloadInput) { i.ExpiresAt = i.ExpiresAt.Add(time.Second) },
		"already stale": func(i *providerLoginPayloadInput) {
			i.IssuedAt = i.ExpiresAt
			i.ExpiresAt = i.IssuedAt.Add(time.Second)
		},
	} {
		t.Run(name, func(t *testing.T) {
			c, anonymous, now, _ := providerLoginPayloadFixture(t)
			input := providerLoginLinkTestInput(t, anonymous, providerLoginLinkTestSession(t, *now, nil), nil)
			mutate(&input)
			if _, err := c.generate(context.Background(), input, 1, risk.PreparedAuthenticationAdmission{}); err == nil {
				t.Fatal("wrong-scope or stale member consent admitted")
			}
		})
	}
	for _, optional := range []string{"organization", "factor", "passkey"} {
		t.Run(optional, func(t *testing.T) {
			c, anonymous, now, _ := providerLoginPayloadFixture(t)
			original := providerLoginLinkTestSession(t, *now, func(spec *session.SessionSpec) {
				a, _ := spec.Authority.Bindings()
				binding := session.OptionalAuthorityBinding{Present: true, Binding: session.AuthorityBinding{ScopeKey: optional, Version: 1}}
				switch optional {
				case "organization":
					a.Organization, a.ActiveOrganizationID = binding, "organization"
				case "factor":
					a.Factor = binding
				case "passkey":
					a.Passkey = binding
				}
				var err error
				spec.Authority, err = session.NewAuthoritySnapshot(a)
				if err != nil {
					t.Fatal(err)
				}
			})
			input := providerLoginLinkTestInput(t, anonymous, original, nil)
			if _, err := c.generate(context.Background(), input, 1, risk.PreparedAuthenticationAdmission{}); err == nil {
				t.Fatal("unsupported optional session authority admitted")
			}
		})
	}
}

func TestProviderLoginLinkPayloadAcceptsSessionIssuedWithinConsentSecond(t *testing.T) {
	c, anonymous, now, _ := providerLoginPayloadFixture(t)
	original := providerLoginLinkTestSession(t, *now, func(spec *session.SessionSpec) {
		spec.IssuedAt = now.Add(time.Millisecond)
		spec.LastActivityAt = spec.IssuedAt
		spec.Authentication.Proof.ExpiresAt = now.Add(time.Minute)
	})
	*now = now.Add(500 * time.Millisecond)
	input := providerLoginLinkTestInput(t, anonymous, original, func(i *providerLoginLinkTestIntent) { i.ConsentedAt = *now })
	if _, err := c.generate(context.Background(), input, 1, risk.PreparedAuthenticationAdmission{}); err != nil {
		t.Fatal("second-aligned grant rejected the original session from earlier in the same second", err)
	}
}

func TestProviderLoginLinkPayloadRejectsIncompleteConsent(t *testing.T) {
	for name, mutate := range map[string]func(*providerLoginLinkTestIntent){
		"missing session":        func(i *providerLoginLinkTestIntent) { i.OriginalSession = nil },
		"renewed consent second": func(i *providerLoginLinkTestIntent) { i.ConsentedAt = i.ConsentedAt.Add(time.Second) },
		"duplicate field": func(i *providerLoginLinkTestIntent) {
			i.OriginalSession = append(i.OriginalSession, i.OriginalSession[0])
		},
		"missing organization epoch":            func(i *providerLoginLinkTestIntent) { i.OrganizationVersion = 0 },
		"missing organization credential epoch": func(i *providerLoginLinkTestIntent) { i.OrganizationCredentialVersion = 0 },
		"missing membership epoch":              func(i *providerLoginLinkTestIntent) { i.MembershipVersion = 0 },
		"missing authorization epoch":           func(i *providerLoginLinkTestIntent) { i.AuthorizationVersion = 0 },
		"missing factor epoch":                  func(i *providerLoginLinkTestIntent) { i.FactorVersion = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			c, anonymous, now, _ := providerLoginPayloadFixture(t)
			input := providerLoginLinkTestInput(t, anonymous, providerLoginLinkTestSession(t, *now, nil), mutate)
			if _, err := c.generate(context.Background(), input, 1, risk.PreparedAuthenticationAdmission{}); err == nil {
				t.Fatal("incomplete member consent admitted")
			}
		})
	}
}

func TestProviderLoginLinkPayloadRequiresOriginalLocalPasswordCookie(t *testing.T) {
	for _, profile := range []string{"non-password", "different purpose", "different assurance", "missing csrf", "continued password", "expired idle lifetime"} {
		t.Run(profile, func(t *testing.T) {
			c, anonymous, now, _ := providerLoginPayloadFixture(t)
			original := providerLoginLinkTestSession(t, *now, func(spec *session.SessionSpec) {
				switch profile {
				case "non-password":
					spec.Authentication.Proof.Method = "oauth"
				case "different purpose":
					spec.Authentication.Proof.Purpose = "other-purpose"
				case "different assurance":
					spec.Authentication.Proof.Assurance = authentication.AssuranceMultiFactor
				case "expired idle lifetime":
					policy, err := session.NewRememberPolicy(session.RememberPolicySpec{Choice: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 5 * time.Minute, RefreshAfter: time.Minute, FreshFor: 15 * time.Minute})
					if err != nil {
						t.Fatal(err)
					}
					spec.Remember = policy
					spec.LastActivityAt = now.Add(-6 * time.Minute)
				}
			})
			var err error
			switch profile {
			case "missing csrf":
				spec, _ := original.Bindings()
				original, err = session.NewSession(spec)
			case "continued password":
				spec, _ := original.Bindings()
				a, _ := spec.Authority.Bindings()
				original, err = session.ContinuePasswordSession(original, session.CredentialContinuationSpec{CommandID: "BAQEBAQEBAQEBAQEBAQEBA", BeforeAuthorityVersion: a.Credential.Version, BeforeCredentialVersion: spec.Authentication.CredentialVersion})
			}
			if err != nil {
				t.Fatal(err)
			}
			input := providerLoginLinkTestInput(t, anonymous, original, nil)
			if _, err := c.generate(context.Background(), input, 1, risk.PreparedAuthenticationAdmission{}); err == nil {
				t.Fatal("unsupported original local session admitted")
			}
		})
	}
}

func TestProviderLoginLinkPayloadKeepsAnonymousEncodingUnchanged(t *testing.T) {
	_, input, _, _ := providerLoginPayloadFixture(t)
	legacy := struct {
		Command                                                   identity.CommandBinding
		OrganizationID, ProviderID, Issuer, ClientID, RedirectURI string
		ProviderVersion, CredentialGeneration, MappingVersion     uint64
		InputFingerprint                                          [32]byte
		IssuedAt, ExpiresAt                                       time.Time
		BrowserOrigin, SuccessCallback, ErrorCallback             string
		Remember                                                  session.RememberPolicySpec
	}{input.Command, input.OrganizationID, input.ProviderID, input.Issuer, input.ClientID, input.RedirectURI, input.ProviderVersion, input.CredentialGeneration, input.MappingVersion, input.InputFingerprint, input.IssuedAt, input.ExpiresAt, input.BrowserOrigin, input.SuccessCallback, input.ErrorCallback, input.Remember}
	want, err := providerLoginPayloadEncode(legacy)
	if err != nil {
		t.Fatal(err)
	}
	got, err := providerLoginPayloadEncode(input)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatal("optional member consent changed legacy anonymous input bytes", err)
	}
	var decoded providerLoginPayloadInput
	if providerLoginPayloadDecode(want, &decoded) != nil || !reflect.DeepEqual(decoded, input) {
		t.Fatal("legacy anonymous input no longer decodes unchanged")
	}
	if strings.Contains(fmt.Sprintf("%#v", input), "enterprise") {
		t.Fatal("payload formatting disclosed original input")
	}
}
