//go:build integration

package postgres_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"math/big"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

func TestNativeSAMLMetadataReadUsesOnlyCurrentInstalledSigner(t *testing.T) {
	x := newSAMLStartFixture(t)
	f, selected := x.start.enable.f, x.profiles[0]
	const exactSigner = "fixture-activation-SP-signing/fixture-activation-SP-signing/"
	now := time.Now().UTC().Truncate(time.Second)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	makeCertificate := func(expiry time.Time) []byte {
		t.Helper()
		template := &x509.Certificate{SerialNumber: big.NewInt(42), NotBefore: now.Add(-time.Hour), NotAfter: expiry, KeyUsage: x509.KeyUsageDigitalSignature}
		der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
	expiry := now.Add(time.Hour)
	certificate := makeCertificate(expiry)
	projected := certificate
	projectedExpiry := expiry
	var changeInstallation func(context.Context) error
	calls := 0
	owner, err := ssopg.NewProviderSAMLMetadataService(x.start.service, func(ctx context.Context, bundle []byte, at time.Time) ([]byte, time.Time, error) {
		calls++
		if _, bounded := ctx.Deadline(); !bounded || string(bundle) != exactSigner || at.Before(now) {
			t.Fatal("projection did not receive bounded current signer custody")
		}
		if changeInstallation != nil {
			if err := changeInstallation(ctx); err != nil {
				t.Fatal("disable the installed signer during projection", err)
			}
		}
		return projected, projectedExpiry, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	assertDenied := func(tenant identity.TenantID, provider sso.ProviderID) {
		t.Helper()
		got, err := owner.Read(f.ctx, tenant, provider)
		if err == nil || got.EntityID != "" || got.AssertionConsumerURL != "" || len(got.SigningCertificate) != 0 || !got.ValidUntil.IsZero() {
			t.Fatal("denial disclosed SP metadata")
		}
	}
	assertDenied(identity.TenantID("unselected-tenant"), selected.ProviderID)
	assertDenied(x.start.enable.proof.TenantID, "unselected-provider")
	if calls != 0 {
		t.Fatal("foreign scope reached installed signer projection")
	}
	got, err := owner.Read(f.ctx, x.start.enable.proof.TenantID, selected.ProviderID)
	base := selected.TrustedOrigin + "/saml2/" + string(selected.ProviderID)
	if err != nil || got.EntityID != base+"/metadata" || got.AssertionConsumerURL != base+"/acs" ||
		!bytes.Equal(got.SigningCertificate, certificate) || !time.Now().Before(got.ValidUntil) || got.ValidUntil.After(now.Add(20*time.Second)) {
		t.Fatal("installed SP projection did not retain exact useful public data", err)
	}
	got.SigningCertificate[0] = 0
	next, err := owner.Read(f.ctx, x.start.enable.proof.TenantID, selected.ProviderID)
	if err != nil || !bytes.Equal(next.SigningCertificate, certificate) || certificate[0] == 0 {
		t.Fatal("metadata did not own detached public certificate bytes", err)
	}
	projected, projectedExpiry = []byte(exactSigner), expiry
	assertDenied(x.start.enable.proof.TenantID, selected.ProviderID)
	projected, projectedExpiry = makeCertificate(now), now
	assertDenied(x.start.enable.proof.TenantID, selected.ProviderID)
	projected, projectedExpiry = certificate, expiry
	disposition, err := sso.NewActiveTransactionDisposition(selected.ProviderID, selected.ProviderVersion, sso.ActiveTransactionRevoke)
	if err != nil {
		t.Fatal(err)
	}
	changeInstallation = func(ctx context.Context) error {
		_, err := x.start.enable.service.ProviderDisableSAML(ctx, sso.ProviderDisableRequest{
			ProviderID: string(selected.ProviderID), ExpectedVersion: selected.ProviderVersion,
			Reason: "Retire SAML SP metadata selection", ActiveTransactionDisposition: disposition,
		})
		return err
	}
	assertDenied(x.start.enable.proof.TenantID, selected.ProviderID)
	changeInstallation = nil
	assertDenied(x.start.enable.proof.TenantID, selected.ProviderID)
}
