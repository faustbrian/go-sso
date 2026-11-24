//go:build integration

package postgres_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"strconv"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
	"github.com/faustbrian/go-sso/saml"
)

func TestNativeSAMLIDPCertificateRotationPreservesSPCredentialsAndInstalledIdentity(t *testing.T) {
	keys := make([]*ecdsa.PrivateKey, 2)
	certificates := make([][]byte, 2)
	now := time.Now().UTC()
	for i := range keys {
		var err error
		keys[i], err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal("generate isolated IdP signing key", err)
		}
		template := &x509.Certificate{SerialNumber: big.NewInt(int64(i + 1)),
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
		certificates[i], err = x509.CreateCertificate(rand.Reader, template, template, &keys[i].PublicKey, keys[i])
		if err != nil {
			t.Fatal("create isolated IdP signing certificate", err)
		}
	}
	x := newProviderSAMLActivationFixtureWithBundle(t, discoveryFixtureTenant, nil, certificates[0])
	f, provider := x.f, x.request.ProviderID
	before := nativeSAMLIDPPinSnapshot(t, x)
	original := nativeSAMLIDPPinConfiguration(t, x, 2)
	if !reflect.DeepEqual(original.IdP.SigningCertificates, [][]byte{certificates[0]}) || before.generation != "1" || before.credentialVersion != "2" {
		t.Fatal("fixture did not install the original IdP pin and separate SP signer generation")
	}
	var pinValidations, spValidations int
	base, err := x.service.WithSAMLRegistration("https://sso.example.com", func(ctx context.Context, issuer, endpoint string, pins [][]byte) error {
		pinValidations++
		if _, bounded := ctx.Deadline(); !bounded || issuer != original.IdP.EntityID || endpoint != original.IdP.RedirectEndpoint {
			return sso.ErrInvalidInput
		}
		return saml.ValidateRegistration(ctx, issuer, endpoint, pins)
	})
	if err != nil {
		t.Fatal(err)
	}
	base, err = base.WithSAMLSigningCredentialValidator(func(ctx context.Context, bundle []byte, at time.Time) (time.Time, error) {
		spValidations++
		if _, bounded := ctx.Deadline(); !bounded || ctx.Err() != nil || !bytes.Equal(bundle, bytes.Repeat([]byte("fixture-activation-SP-signing/"), 2)) {
			return time.Time{}, sso.ErrInvalidInput
		}
		return at.Add(30 * time.Minute), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	credentials := nativeCredentialService(t, base)
	request := nativeSAMLIDPPinRequest(t, x, 2, 3, certificates[1])
	wrongGeneration := request.CredentialReference.Context()
	wrongGeneration.Generation = 2
	if _, err := wrongGeneration.EncryptionContext(); !errors.Is(err, sso.ErrInvalidInput) {
		t.Fatal("IdP pin ingress accepted the next SP generation instead of its exact metadata successor", err)
	}
	if after := nativeSAMLIDPPinSnapshot(t, x); !reflect.DeepEqual(after, before) {
		t.Fatal("rejected IdP generation changed provider or credential custody")
	}
	malformed := nativeSAMLIDPPinRequest(t, x, 2, 3, []byte("not a DER certificate"))
	if denied, err := credentials.ProviderCredentialsRotate(f.ctx, malformed); !errors.Is(err, sso.ErrInvalidInput) || denied.Active || denied.Completion.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("malformed IdP certificate did not return a typed validation denial", err)
	}
	if after := nativeSAMLIDPPinSnapshot(t, x); !reflect.DeepEqual(after, before) {
		t.Fatal("malformed IdP signing certificate changed provider or credential custody")
	}
	validatedBeforeRotation := pinValidations

	rotated, err := credentials.ProviderCredentialsRotate(f.ctx, request)
	if err != nil || rotated.ProviderID != provider || rotated.Version != 3 || !rotated.Active || rotated.ReconciliationRequired ||
		rotated.Completion.Outcome != identity.CommitOutcomeCommitted || rotated.Completion.Binding.OperationID != "identity.sso.provider.credentials-rotate" {
		t.Fatal("replace only the installed IdP signing pins on the disabled provider", err)
	}
	if pinValidations != validatedBeforeRotation+1 || spValidations != 0 {
		t.Fatal("IdP pin replacement skipped native certificate validation or used the SP signing validator")
	}
	after := nativeSAMLIDPPinSnapshot(t, x)
	want := before
	want.version, want.effects, want.audits, want.events = "3", before.effects+1, before.audits+1, before.events+1
	if !reflect.DeepEqual(after, want) {
		t.Fatal("IdP pin replacement changed SP custody, provider identity, mapping, domains or exactly-once effects")
	}
	installed := nativeSAMLIDPPinConfiguration(t, x, 3)
	wantConfiguration := original
	wantConfiguration.IdP.SigningCertificates = [][]byte{certificates[1]}
	if !reflect.DeepEqual(installed, wantConfiguration) {
		t.Fatal("pin rotation replaced more than the exact configured IdP certificate set")
	}
	validated := pinValidations
	if retry, err := credentials.ProviderCredentialsRotate(f.ctx, request); err != nil || !reflect.DeepEqual(retry, rotated) {
		t.Fatal("original IdP pin rotation did not recover its exact result", err)
	}
	if pinValidations != validated || spValidations != 0 || !reflect.DeepEqual(nativeSAMLIDPPinSnapshot(t, x), after) {
		t.Fatal("original IdP pin retry repeated validation or changed durable custody")
	}
	proof, err := x.config.Organizations.GetDomainProof(f.ctx, organization.DomainProofKey(x.proof))
	if err != nil || proof != x.proof {
		t.Fatal("pin rotation changed organization-owned domain proof", err)
	}
	checkpoint, err := base.ObserveSAMLProviderCredentialCheckpoint(f.ctx, provider, 3)
	if err != nil {
		t.Fatal("observe unchanged SP signing custody at the new provider version", err)
	}
	bindings, err := checkpoint.Bindings()
	if err != nil || bindings.ProviderVersion != 3 || bindings.Generation != 1 {
		t.Fatal("pin replacement advanced the detached SP signing generation", err)
	}
	enable := x.request
	enable.ExpectedVersion, enable.CredentialCheckpoint = 3, checkpoint
	enabled, err := base.ProviderEnable(f.ctx, enable)
	if err != nil || !enabled.Provider.Enabled || enabled.Provider.ID != provider || enabled.Provider.Version != 4 ||
		enabled.Completion.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("enable the same provider after replacing IdP pins", err)
	}
	enabledState := nativeSAMLIDPPinSnapshot(t, x)
	current := nativeSAMLIDPPinRequest(t, x, 4, 5, certificates[0])
	if denied, err := credentials.ProviderCredentialsRotate(f.ctx, current); !errors.Is(err, sso.ErrInvalidInput) || denied.Active || denied.Completion.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("current enabled provider accepted IdP certificate replacement", err)
	}
	if !reflect.DeepEqual(nativeSAMLIDPPinSnapshot(t, x), enabledState) {
		t.Fatal("enabled-provider denial changed provider, signer custody or rotation effects")
	}
	if retry, err := credentials.ProviderCredentialsRotate(f.ctx, request); err != nil || !reflect.DeepEqual(retry, rotated) {
		t.Fatal("historical IdP pin result was not recoverable after enabling its successor", err)
	}
	nativeSAMLIDPPinVerifyInstalledResponse(t, x, enabled.Provider, keys[1], keys[0])
}

func nativeSAMLIDPPinRequest(t *testing.T, x providerEnableFixture, version, generation uint64, certificate []byte) sso.ProviderCredentialsRotateRequest {
	t.Helper()
	plain, err := sso.EncodeSAMLIDPSigningCertificates([][]byte{certificate})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(plain)
	var at time.Time
	if err := x.f.pool.Raw().QueryRow(x.f.ctx, `SELECT clock_timestamp()`).Scan(&at); err != nil {
		t.Fatal(err)
	}
	at = at.UTC().Truncate(time.Microsecond)
	binding := sso.CredentialReferenceContext{TenantID: string(x.proof.TenantID), OrganizationID: string(x.proof.OrganizationID),
		ProviderID: x.request.ProviderID, Protocol: "saml", Purpose: sso.SAMLIDPSigningCertificatesPurpose,
		ProviderVersion: version, Generation: generation, Audience: "identity.sso.provider.credentials-rotate",
		EnvelopeKeyID: x.config.KeyReference, IssuedAt: at, ExpiresAt: at.Add(time.Minute)}
	aad, err := binding.EncryptionContext()
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := x.config.Envelope.Encrypt(x.f.ctx, envelope.EncryptRequest{Plaintext: plain, KeyReference: x.config.KeyReference, Context: aad})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := sealed.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	reference, err := sso.NewEncryptedCredentialReference(x.f.ctx, x.config.Envelope, wire, binding)
	if err != nil {
		t.Fatal("authenticate exact IdP pin replacement ingress", err)
	}
	return sso.ProviderCredentialsRotateRequest{CommandID: commandID(t), ProviderID: x.request.ProviderID, ExpectedVersion: version,
		CredentialReference: reference, OverlapPolicy: sso.NewNoCredentialOverlapPolicy()}
}

type nativeSAMLIDPPinState struct {
	version, generation, credentialVersion string
	issuer, spEnvelope, spContext          []byte
	mapping                                string
	pending                                int
	enabled                                bool
	effects, audits, events                int
}

func nativeSAMLIDPPinSnapshot(t *testing.T, x providerEnableFixture) nativeSAMLIDPPinState {
	t.Helper()
	var state nativeSAMLIDPPinState
	err := x.f.pool.Raw().QueryRow(x.f.ctx, `SELECT p.metadata_version::text,p.issuer_digest,
 COALESCE(p.metadata_mapping_version,p.mapping_version)::text,p.pending_domains,p.enabled,
 c.generation::text,c.provider_version::text,c.envelope,c.credential_context,
 (SELECT count(*) FROM sso_providers.credential_effects),
 (SELECT count(*) FROM audit.records WHERE action='identity.sso.provider.credentials-rotate' AND outcome=1),
 (SELECT count(*) FROM outbox_messages WHERE topic='sso.provider_credentials_rotated.v1')
 FROM sso_providers.providers p JOIN sso_providers.credentials c USING(tenant_id,organization_id,provider_id)
 WHERE p.tenant_id=$1 AND p.organization_id=$2 AND p.provider_id=$3`, string(x.proof.TenantID), string(x.proof.OrganizationID), x.request.ProviderID).
		Scan(&state.version, &state.issuer, &state.mapping, &state.pending, &state.enabled, &state.generation, &state.credentialVersion,
			&state.spEnvelope, &state.spContext, &state.effects, &state.audits, &state.events)
	if err != nil {
		t.Fatal("read fixture-owned provider and separate SP custody", err)
	}
	return state
}

type nativeSAMLIDPPinInstalledConfiguration struct {
	IdP     sso.SAMLConfigurationSpec
	Origin  string
	Mapping sso.AttributeMappingSpec
	Domains []string
}

func nativeSAMLIDPPinConfiguration(t *testing.T, x providerEnableFixture, version uint64) nativeSAMLIDPPinInstalledConfiguration {
	t.Helper()
	var wire []byte
	if err := x.f.pool.Raw().QueryRow(x.f.ctx, `SELECT COALESCE(metadata_configuration_envelope,configuration_envelope)
 FROM sso_providers.providers WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3`,
		string(x.proof.TenantID), string(x.proof.OrganizationID), x.request.ProviderID).Scan(&wire); err != nil {
		t.Fatal("read fixture-owned encrypted IdP configuration", err)
	}
	sealed, err := envelope.ParseEnvelope(wire)
	if err != nil {
		t.Fatal(err)
	}
	aad, err := envelope.NewContext(map[string]string{"owner": "sso/provider", "tenant": string(x.proof.TenantID),
		"organization": string(x.proof.OrganizationID), "provider": x.request.ProviderID,
		"protocol": "saml", "purpose": "static-configuration", "version": strconv.FormatUint(version, 10)})
	if err != nil {
		t.Fatal(err)
	}
	plain, err := x.config.Envelope.Decrypt(x.f.ctx, envelope.DecryptRequest{Envelope: sealed, Context: aad})
	defer clear(plain)
	if err != nil {
		t.Fatal("authenticate fixture-owned IdP metadata at its exact provider version", err)
	}
	var configuration nativeSAMLIDPPinInstalledConfiguration
	if err := json.Unmarshal(plain, &configuration); err != nil {
		t.Fatal("decode installed IdP configuration", err)
	}
	return configuration
}

func nativeSAMLIDPPinVerifyInstalledResponse(t *testing.T, x providerEnableFixture, provider sso.Provider, current, retired *ecdsa.PrivateKey) {
	t.Helper()
	router, err := newProviderRouter(t, x, 4).WithProtocolRegistry()
	if err != nil {
		t.Fatal(err)
	}
	router, err = router.WithSAMLRouteValidation(func(ctx context.Context, bundle []byte, at time.Time) (time.Time, error) {
		if _, bounded := ctx.Deadline(); !bounded || ctx.Err() != nil || !bytes.Equal(bundle, bytes.Repeat([]byte("fixture-activation-SP-signing/"), 2)) {
			return time.Time{}, sso.ErrInvalidInput
		}
		return at.Add(time.Minute), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	profile := ssopg.StaticSAMLLoginProfile{ProviderID: sso.ProviderID(provider.ID), OrganizationID: x.proof.OrganizationID,
		Domain: x.proof.Domain, TrustedOrigin: "https://sso.example.com", ProviderVersion: provider.Version,
		CredentialGeneration: 1, MappingVersion: provider.MappingVersion}
	owner, err := ssopg.NewProviderSAMLIDPAdmissionService(router, ssopg.ProviderSAMLIDPAdmissionConfig{
		TenantID: x.proof.TenantID, Profiles: []ssopg.StaticSAMLIDPAdmissionProfile{{Provider: profile, MaximumAge: time.Minute}},
		Verify: func(ctx context.Context, input ssopg.SAMLIDPResponseVerificationInput) (ssopg.SAMLVerifiedResponse, error) {
			wire, err := saml.NewIDPInitiatedPOSTResponseProfile(saml.IDPInitiatedPOSTResponseConfig{
				SPEntityID: input.SPEntityID, IdentityProviderEntityID: input.IdentityProviderEntityID,
				ExternalOrigin: input.ExternalOrigin, ProviderID: string(input.ProviderID),
				SigningCertificates: input.SigningCertificates, MaximumAge: input.MaximumAge})
			if err != nil {
				return ssopg.SAMLVerifiedResponse{}, err
			}
			verified, err := wire.Validate(ctx, saml.IDPInitiatedPOSTResponseInput{SAMLResponse: input.SAMLResponse, Now: input.Now})
			if err != nil {
				return ssopg.SAMLVerifiedResponse{}, err
			}
			evidence, err := verified.Evidence()
			return ssopg.SAMLVerifiedResponse(evidence), err
		},
	})
	if err != nil {
		t.Fatal("compose public installed-provider admission with native XML verification", err)
	}
	request := ssopg.SAMLIDPAdmissionRequest{TenantID: x.proof.TenantID, ProviderID: profile.ProviderID,
		ReceivedAssertionConsumerURL: profile.TrustedOrigin + "/saml2/" + provider.ID + "/idp-init"}
	request.SAMLResponse = nativeSAMLIDPPinResponse(t, current, profile)
	admitted, err := owner.Verify(x.f.ctx, request)
	if err != nil {
		t.Fatal("fresh response signed by replacement pin did not pass installed-provider admission", err)
	}
	evidence, err := admitted.Evidence()
	if err != nil || evidence.ProviderSubject != nativeSAMLCallbackSubject {
		t.Fatal("replacement pin did not authenticate the signed provider subject", err)
	}
	request.SAMLResponse = nativeSAMLIDPPinResponse(t, retired, profile)
	assertNativeSAMLIDPDenied(t, owner, x.f.ctx, request)
}

func nativeSAMLIDPPinResponse(t *testing.T, key *ecdsa.PrivateKey, profile ssopg.StaticSAMLLoginProfile) string {
	t.Helper()
	signer := nativeSAMLRoleJourneyFixture{key: key}
	now := time.Now().UTC().Truncate(time.Microsecond)
	issued, expires := now.Format(time.RFC3339Nano), now.Add(time.Minute).Format(time.RFC3339Nano)
	acs := profile.TrustedOrigin + "/saml2/" + string(profile.ProviderID) + "/idp-init"
	entity := profile.TrustedOrigin + "/saml2/" + string(profile.ProviderID) + "/metadata"
	const assertionID, responseID = "_rotated-pin-assertion", "_rotated-pin-response"
	issuer := `<a:Issuer>` + nativeSAMLCallbackIssuer + `</a:Issuer>`
	assertionOpen := fmt.Sprintf(`<a:Assertion xmlns:a="urn:oasis:names:tc:SAML:2.0:assertion" ID="%s" IssueInstant="%s" Version="2.0">`, assertionID, issued)
	content := `<a:Subject><a:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">` + nativeSAMLCallbackSubject + `</a:NameID>` +
		`<a:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">` +
		fmt.Sprintf(`<a:SubjectConfirmationData NotOnOrAfter="%s" Recipient="%s"></a:SubjectConfirmationData>`, expires, acs) +
		`</a:SubjectConfirmation></a:Subject>` +
		fmt.Sprintf(`<a:Conditions NotBefore="%s" NotOnOrAfter="%s"><a:AudienceRestriction><a:Audience>%s</a:Audience></a:AudienceRestriction></a:Conditions>`, issued, expires, entity) +
		fmt.Sprintf(`<a:AuthnStatement AuthnInstant="%s" SessionIndex="rotation-session"><a:AuthnContext><a:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</a:AuthnContextClassRef></a:AuthnContext></a:AuthnStatement></a:Assertion>`, issued)
	assertion := assertionOpen + issuer + signer.signXML(t, assertionID, assertionOpen+issuer+content) + content
	responseOpen := fmt.Sprintf(`<p:Response xmlns:p="urn:oasis:names:tc:SAML:2.0:protocol" Destination="%s" ID="%s" IssueInstant="%s" Version="2.0">`, acs, responseID, issued)
	responseIssuer := `<a:Issuer xmlns:a="urn:oasis:names:tc:SAML:2.0:assertion">` + nativeSAMLCallbackIssuer + `</a:Issuer>`
	responseContent := `<p:Status><p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"></p:StatusCode></p:Status>` + assertion + `</p:Response>`
	response := responseOpen + responseIssuer + signer.signXML(t, responseID, responseOpen+responseIssuer+responseContent) + responseContent
	return base64.StdEncoding.EncodeToString([]byte(response))
}
