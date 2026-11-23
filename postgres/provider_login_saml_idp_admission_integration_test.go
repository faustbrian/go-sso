//go:build integration

package postgres_test

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"strconv"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

const nativeSAMLIDPResponse = "synthetic-trusted-unsolicited-response-not-XML"

type nativeSAMLIDPAdmissionFixture struct {
	enable      providerEnableFixture
	router      *ssopg.ProviderRouter
	profile     ssopg.StaticSAMLLoginProfile
	installed   sso.SAMLConfigurationSpec
	routeExpiry time.Time
}

func newNativeSAMLIDPAdmissionFixture(t *testing.T) *nativeSAMLIDPAdmissionFixture {
	t.Helper()
	x := newProviderSAMLActivationFixtureForTenant(t, discoveryFixtureTenant)
	enabled, err := x.service.ProviderEnable(x.f.ctx, x.request)
	if err != nil || enabled.Completion.Outcome != identity.CommitOutcomeCommitted || !enabled.Provider.Enabled {
		t.Fatal("enable SAML directly without an SP start or browser", err)
	}
	f := &nativeSAMLIDPAdmissionFixture{
		enable: x,
		profile: ssopg.StaticSAMLLoginProfile{ProviderID: sso.ProviderID(enabled.Provider.ID),
			OrganizationID: x.proof.OrganizationID, Domain: x.proof.Domain, TrustedOrigin: "https://sso.example.com",
			ProviderVersion: enabled.Provider.Version, CredentialGeneration: 1, MappingVersion: enabled.Provider.MappingVersion},
		routeExpiry: time.Now().UTC().Add(time.Hour).Truncate(time.Microsecond),
	}
	var wire []byte
	if err := x.f.pool.Raw().QueryRow(x.f.ctx, `SELECT metadata_configuration_envelope FROM sso_providers.providers
 WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3`, string(x.proof.TenantID), string(x.proof.OrganizationID), enabled.Provider.ID).Scan(&wire); err != nil {
		t.Fatal("read the fixture's exact installed IdP trust", err)
	}
	sealed, err := envelope.ParseEnvelope(wire)
	if err != nil {
		t.Fatal(err)
	}
	aad, err := envelope.NewContext(map[string]string{"owner": "sso/provider", "tenant": string(x.proof.TenantID),
		"organization": string(x.proof.OrganizationID), "provider": enabled.Provider.ID, "protocol": "saml",
		"purpose": "static-configuration", "version": strconv.FormatUint(enabled.Provider.Version, 10)})
	if err != nil {
		t.Fatal(err)
	}
	plain, err := x.config.Envelope.Decrypt(x.f.ctx, envelope.DecryptRequest{Envelope: sealed, Context: aad})
	defer clear(plain)
	if err != nil {
		t.Fatal("open fixture-owned installed metadata", err)
	}
	var stored struct{ IdP sso.SAMLConfigurationSpec }
	if err := json.Unmarshal(plain, &stored); err != nil || len(stored.IdP.SigningCertificates) != 1 {
		t.Fatal("decode installed IdP trust", err)
	}
	f.installed = stored.IdP
	router, err := newProviderRouter(t, x, 4).WithProtocolRegistry()
	if err != nil {
		t.Fatal(err)
	}
	f.router, err = router.WithSAMLRouteValidation(func(ctx context.Context, bundle []byte, at time.Time) (time.Time, error) {
		if _, bounded := ctx.Deadline(); !bounded || ctx.Err() != nil ||
			!bytes.Equal(bundle, bytes.Repeat([]byte("fixture-activation-SP-signing/"), 2)) || !at.Before(f.routeExpiry) {
			return time.Time{}, sso.ErrInvalidInput
		}
		return f.routeExpiry, nil
	})
	if err != nil {
		t.Fatal("select current native SAML route validation", err)
	}
	return f
}

func (f *nativeSAMLIDPAdmissionFixture) request() ssopg.SAMLIDPAdmissionRequest {
	return ssopg.SAMLIDPAdmissionRequest{TenantID: f.enable.proof.TenantID, ProviderID: f.profile.ProviderID,
		ReceivedAssertionConsumerURL: f.profile.TrustedOrigin + "/saml2/" + string(f.profile.ProviderID) + "/idp-init",
		SAMLResponse:                 nativeSAMLIDPResponse}
}

func (f *nativeSAMLIDPAdmissionFixture) assertVerifierInput(t *testing.T, ctx context.Context, input ssopg.SAMLIDPResponseVerificationInput, maximumAge time.Duration) {
	t.Helper()
	deadline, bounded := ctx.Deadline()
	if !bounded || ctx.Err() != nil || input.Now.IsZero() || !input.Now.Before(deadline) || deadline.After(time.Now().Add(3*time.Second)) ||
		input.SPEntityID != f.profile.TrustedOrigin+"/saml2/"+string(f.profile.ProviderID)+"/metadata" ||
		input.IdentityProviderEntityID != f.installed.EntityID || input.ExternalOrigin != f.profile.TrustedOrigin ||
		input.ProviderID != f.profile.ProviderID || input.AssertionConsumerURL != f.request().ReceivedAssertionConsumerURL ||
		input.SAMLResponse != nativeSAMLIDPResponse || input.MaximumAge != maximumAge ||
		!reflect.DeepEqual(input.SigningCertificates, f.installed.SigningCertificates) {
		t.Fatal("unsolicited verifier did not receive bounded exact installed trust, destination and selected age")
	}
}

func nativeSAMLIDPEvidence(now time.Time) ssopg.SAMLVerifiedResponse {
	return ssopg.SAMLVerifiedResponse{ResponseID: "_native-idp-response", AssertionID: "_native-idp-assertion",
		ProviderSubject: "existing-native-idp-member", SubjectFormat: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
		SessionIndex: "native-idp-session", AssertionExpiresAt: now.Add(time.Minute).Truncate(time.Microsecond),
		ValidUntil: now.Add(time.Minute).Truncate(time.Microsecond)}
}

func assertNativeSAMLIDPDenied(t *testing.T, owner *ssopg.ProviderSAMLIDPAdmissionService, ctx context.Context, request ssopg.SAMLIDPAdmissionRequest) {
	t.Helper()
	got, err := owner.Verify(ctx, request)
	evidence, evidenceErr := got.Evidence()
	if err == nil || evidenceErr == nil || !reflect.DeepEqual(evidence, ssopg.SAMLVerifiedResponse{}) {
		t.Fatal("denied unsolicited response disclosed usable detached evidence", err, evidenceErr)
	}
}

func TestNativeSAMLIDPAdmissionWithoutSPStartUsesInstalledTrustAndEarliestCutoff(t *testing.T) {
	f := newNativeSAMLIDPAdmissionFixture(t)
	for _, name := range []string{"wire", "native-age", "original-route"} {
		t.Run(name, func(t *testing.T) {
			maximumAge := 5 * time.Minute
			if name == "native-age" {
				maximumAge = time.Second
			}
			f.routeExpiry = time.Now().UTC().Add(4 * time.Second).Truncate(time.Microsecond)
			originalRouteExpiry := f.routeExpiry
			var supplied ssopg.SAMLVerifiedResponse
			var wantCutoff time.Time
			calls := 0
			owner, err := ssopg.NewProviderSAMLIDPAdmissionService(f.router, ssopg.ProviderSAMLIDPAdmissionConfig{
				TenantID: f.enable.proof.TenantID,
				Profiles: []ssopg.StaticSAMLIDPAdmissionProfile{{Provider: f.profile, MaximumAge: maximumAge}},
				Verify: func(ctx context.Context, input ssopg.SAMLIDPResponseVerificationInput) (ssopg.SAMLVerifiedResponse, error) {
					calls++
					f.assertVerifierInput(t, ctx, input, maximumAge)
					supplied = nativeSAMLIDPEvidence(input.Now)
					switch name {
					case "wire":
						supplied.ValidUntil = input.Now.Add(time.Second).Truncate(time.Microsecond)
						wantCutoff = supplied.ValidUntil
					case "native-age":
						wantCutoff = input.Now.Add(maximumAge)
					case "original-route":
						wantCutoff = originalRouteExpiry
					}
					f.routeExpiry = input.Now.Add(time.Hour)
					return supplied, nil
				},
			})
			if err != nil {
				t.Fatal("compose explicit native unsolicited selection without an SP service", err)
			}
			admitted, err := owner.Verify(f.enable.f.ctx, f.request())
			if err != nil {
				t.Fatal("admit installed unsolicited response without prior SP correlation", err)
			}
			evidence, err := admitted.Evidence()
			want := supplied
			want.ValidUntil = wantCutoff
			if err != nil || calls != 1 || !reflect.DeepEqual(evidence, want) || !time.Now().Before(evidence.ValidUntil) {
				t.Fatal("native admission lost verified scalars or extended the earliest original deadline", err)
			}
		})
	}
	var starts, transactions int
	if err := f.enable.f.pool.Raw().QueryRow(f.enable.f.ctx, `SELECT
 (SELECT count(*) FROM identity.commands WHERE purpose='identity.sso.saml-start'),
 (SELECT count(*) FROM sso_providers.login_transactions)`).Scan(&starts, &transactions); err != nil || starts != 0 || transactions != 0 {
		t.Fatal("read-only unsolicited admission required or created an SP start", starts, transactions, err)
	}
}

func TestNativeSAMLIDPAdmissionRejectsWrongDestinationAndUnselectedScopeBeforeVerifier(t *testing.T) {
	f := newNativeSAMLIDPAdmissionFixture(t)
	calls := 0
	config := ssopg.ProviderSAMLIDPAdmissionConfig{TenantID: f.enable.proof.TenantID,
		Profiles: []ssopg.StaticSAMLIDPAdmissionProfile{{Provider: f.profile, MaximumAge: time.Minute}},
		Verify: func(ctx context.Context, input ssopg.SAMLIDPResponseVerificationInput) (ssopg.SAMLVerifiedResponse, error) {
			calls++
			return nativeSAMLIDPEvidence(input.Now), nil
		}}
	owner, err := ssopg.NewProviderSAMLIDPAdmissionService(f.router, config)
	if err != nil {
		t.Fatal(err)
	}
	base := f.profile.TrustedOrigin + "/saml2/" + string(f.profile.ProviderID)
	for _, destination := range []string{
		"https://foreign.example.com/saml2/" + string(f.profile.ProviderID) + "/idp-init",
		base + "/acs", base + "/idp-init/", base + "/idp-init?alias=true",
		f.profile.TrustedOrigin + "/saml2/foreign-provider/idp-init",
	} {
		t.Run(destination, func(t *testing.T) {
			request := f.request()
			request.ReceivedAssertionConsumerURL = destination
			assertNativeSAMLIDPDenied(t, owner, f.enable.f.ctx, request)
		})
	}
	foreignTenant := f.request()
	foreignTenant.TenantID = "foreign-tenant"
	assertNativeSAMLIDPDenied(t, owner, f.enable.f.ctx, foreignTenant)
	unselectedProvider := f.request()
	unselectedProvider.ProviderID = "unselected-provider"
	unselectedProvider.ReceivedAssertionConsumerURL = f.profile.TrustedOrigin + "/saml2/unselected-provider/idp-init"
	assertNativeSAMLIDPDenied(t, owner, f.enable.f.ctx, unselectedProvider)
	foreignConfig := config
	foreignConfig.TenantID = foreignTenant.TenantID
	foreignOwner, err := ssopg.NewProviderSAMLIDPAdmissionService(f.router, foreignConfig)
	if err != nil {
		t.Fatal(err)
	}
	assertNativeSAMLIDPDenied(t, foreignOwner, f.enable.f.ctx, foreignTenant)
	wrongOriginConfig := config
	wrongOriginConfig.Profiles = []ssopg.StaticSAMLIDPAdmissionProfile{{Provider: f.profile, MaximumAge: time.Minute}}
	wrongOriginConfig.Profiles[0].Provider.TrustedOrigin = "https://foreign.example.com"
	wrongOriginOwner, err := ssopg.NewProviderSAMLIDPAdmissionService(f.router, wrongOriginConfig)
	if err != nil {
		t.Fatal(err)
	}
	wrongOrigin := f.request()
	wrongOrigin.ReceivedAssertionConsumerURL = "https://foreign.example.com/saml2/" + string(f.profile.ProviderID) + "/idp-init"
	assertNativeSAMLIDPDenied(t, wrongOriginOwner, f.enable.f.ctx, wrongOrigin)
	if calls != 0 {
		t.Fatal("foreign scope, SP ACS alias or substituted origin reached the trusted verifier", calls)
	}
}

func TestNativeSAMLIDPAdmissionRejectsInvalidBorrowedVerifierEvidence(t *testing.T) {
	f := newNativeSAMLIDPAdmissionFixture(t)
	for _, name := range []string{"zero", "empty-subject", "duplicate-ids", "unsupported-format", "expired", "missing-assertion-expiry", "verifier-error"} {
		t.Run(name, func(t *testing.T) {
			calls := 0
			owner, err := ssopg.NewProviderSAMLIDPAdmissionService(f.router, ssopg.ProviderSAMLIDPAdmissionConfig{
				TenantID: f.enable.proof.TenantID,
				Profiles: []ssopg.StaticSAMLIDPAdmissionProfile{{Provider: f.profile, MaximumAge: time.Minute}},
				Verify: func(ctx context.Context, input ssopg.SAMLIDPResponseVerificationInput) (ssopg.SAMLVerifiedResponse, error) {
					calls++
					f.assertVerifierInput(t, ctx, input, time.Minute)
					evidence := nativeSAMLIDPEvidence(input.Now)
					switch name {
					case "zero":
						return ssopg.SAMLVerifiedResponse{}, nil
					case "empty-subject":
						evidence.ProviderSubject = ""
					case "duplicate-ids":
						evidence.AssertionID = evidence.ResponseID
					case "unsupported-format":
						evidence.SubjectFormat = "unselected-name-id-format"
					case "expired":
						evidence.ValidUntil = input.Now
					case "missing-assertion-expiry":
						evidence.AssertionExpiresAt = time.Time{}
					case "verifier-error":
						return evidence, sso.ErrForbidden
					}
					return evidence, nil
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			assertNativeSAMLIDPDenied(t, owner, f.enable.f.ctx, f.request())
			if calls != 1 {
				t.Fatal("invalid outcome test did not reach the installed verifier", calls)
			}
		})
	}
}

func TestNativeSAMLIDPAdmissionRechecksProviderDisabledDuringVerification(t *testing.T) {
	f := newNativeSAMLIDPAdmissionFixture(t)
	disposition, err := sso.NewActiveTransactionDisposition(f.profile.ProviderID, f.profile.ProviderVersion, sso.ActiveTransactionRevoke)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	owner, err := ssopg.NewProviderSAMLIDPAdmissionService(f.router, ssopg.ProviderSAMLIDPAdmissionConfig{
		TenantID: f.enable.proof.TenantID,
		Profiles: []ssopg.StaticSAMLIDPAdmissionProfile{{Provider: f.profile, MaximumAge: time.Minute}},
		Verify: func(ctx context.Context, input ssopg.SAMLIDPResponseVerificationInput) (ssopg.SAMLVerifiedResponse, error) {
			calls++
			f.assertVerifierInput(t, ctx, input, time.Minute)
			disabled, err := f.enable.service.ProviderDisableSAML(ctx, sso.ProviderDisableRequest{
				ProviderID: string(f.profile.ProviderID), ExpectedVersion: f.profile.ProviderVersion,
				Reason: "Retire native unsolicited SAML admission", ActiveTransactionDisposition: disposition,
			})
			if err != nil || disabled.Completion.Outcome != identity.CommitOutcomeCommitted || !disabled.Disabled || disabled.ActiveTransactionCount != 0 {
				t.Fatal("disable the selected provider during borrowed verification without SP transactions", err)
			}
			return nativeSAMLIDPEvidence(input.Now), nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	assertNativeSAMLIDPDenied(t, owner, f.enable.f.ctx, f.request())
	if calls != 1 {
		t.Fatal("in-verifier provider mutation was not exercised", calls)
	}
	assertNativeSAMLIDPDenied(t, owner, f.enable.f.ctx, f.request())
	if calls != 1 {
		t.Fatal("disabled provider reached the verifier again", calls)
	}
}

func TestNativeSAMLIDPAdmissionRechecksDomainRevokedDuringVerification(t *testing.T) {
	f := newNativeSAMLIDPAdmissionFixture(t)
	calls := 0
	owner, err := ssopg.NewProviderSAMLIDPAdmissionService(f.router, ssopg.ProviderSAMLIDPAdmissionConfig{
		TenantID: f.enable.proof.TenantID,
		Profiles: []ssopg.StaticSAMLIDPAdmissionProfile{{Provider: f.profile, MaximumAge: time.Minute}},
		Verify: func(ctx context.Context, input ssopg.SAMLIDPResponseVerificationInput) (ssopg.SAMLVerifiedResponse, error) {
			calls++
			f.assertVerifierInput(t, ctx, input, time.Minute)
			revokeEnableTestProof(t, f.enable)
			return nativeSAMLIDPEvidence(input.Now), nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	assertNativeSAMLIDPDenied(t, owner, f.enable.f.ctx, f.request())
	if calls != 1 {
		t.Fatal("in-verifier domain revocation was not exercised", calls)
	}
	assertNativeSAMLIDPDenied(t, owner, f.enable.f.ctx, f.request())
	if calls != 1 {
		t.Fatal("revoked domain reached the verifier again", calls)
	}
}
