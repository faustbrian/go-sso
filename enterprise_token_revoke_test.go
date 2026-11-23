package sso_test

import (
	"bytes"
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-sso"
)

func enterpriseTokenRevokeInputs(t *testing.T) (sso.TokenVersion, identity.IdempotencyKey) {
	t.Helper()
	grant, err := sso.NewTokenVersion(sso.TokenVersionSpec{
		TenantID: "revoke-tenant-sentinel", OrganizationID: "revoke-organization-sentinel",
		ProviderID: "revoke-provider-sentinel", ProviderSubject: " Revoke.Subject:Exact-é ",
		CommandID: "AwMDAwMDAwMDAwMDAwMDAw", CredentialGeneration: 17,
		Version: 29, Purpose: sso.EnterpriseTokenPurpose,
	})
	if err != nil {
		t.Fatal("construct revoke grant", err)
	}
	key, err := identity.NewIdempotencyKey([]byte("Revoke-Retry-Key-Sentinel"))
	if err != nil {
		t.Fatal("construct revoke retry key", err)
	}
	return grant, key
}

func TestRevokeEnterpriseTokenPreservesExactOriginalBindings(t *testing.T) {
	grant, key := enterpriseTokenRevokeInputs(t)
	request, err := sso.NewRevokeEnterpriseToken(grant, key)
	if err != nil {
		t.Fatal("valid revoke request rejected", err)
	}
	gotGrant, gotKey, err := request.Bindings()
	if err != nil || gotGrant != grant || gotKey != key {
		t.Fatal("revoke request changed the original grant or stable retry key")
	}

	copyOfRequest := request
	grant, key = sso.TokenVersion{}, identity.IdempotencyKey{}
	retainedGrant, retainedKey, err := copyOfRequest.Bindings()
	if err != nil || retainedGrant == grant || retainedKey == key || copyOfRequest != request {
		t.Fatal("caller reassignment changed immutable request bindings")
	}
	gotSpec, err := retainedGrant.Spec()
	if err != nil || gotSpec.TenantID != "revoke-tenant-sentinel" ||
		gotSpec.OrganizationID != "revoke-organization-sentinel" || gotSpec.ProviderID != "revoke-provider-sentinel" ||
		gotSpec.ProviderSubject != " Revoke.Subject:Exact-é " || gotSpec.CommandID != "AwMDAwMDAwMDAwMDAwMDAw" ||
		gotSpec.CredentialGeneration != 17 || gotSpec.Version != 29 || gotSpec.Purpose != sso.EnterpriseTokenPurpose {
		t.Fatal("request did not retain the exact original profile, command and generation")
	}

	otherKey, err := identity.NewIdempotencyKey([]byte("Independent-Revoke-Retry-Key"))
	if err != nil {
		t.Fatal(err)
	}
	otherRequest, err := sso.NewRevokeEnterpriseToken(retainedGrant, otherKey)
	if err != nil || otherRequest == request {
		t.Fatal("independent client retry key collapsed into the original request")
	}
	_, projectedOtherKey, err := otherRequest.Bindings()
	if err != nil || projectedOtherKey != otherKey {
		t.Fatal("request did not preserve the independent client key")
	}
}

func TestRevokeEnterpriseTokenRejectsMissingBindings(t *testing.T) {
	grant, key := enterpriseTokenRevokeInputs(t)
	for name, input := range map[string]struct {
		grant sso.TokenVersion
		key   identity.IdempotencyKey
	}{
		"both zero":  {},
		"zero grant": {key: key},
		"zero key":   {grant: grant},
	} {
		t.Run(name, func(t *testing.T) {
			request, err := sso.NewRevokeEnterpriseToken(input.grant, input.key)
			if err != sso.ErrInvalidInput || request != (sso.RevokeEnterpriseToken{}) {
				t.Fatal("missing binding produced a usable request or disclosed input")
			}
			gotGrant, gotKey, err := request.Bindings()
			if err != sso.ErrInvalidInput || gotGrant != (sso.TokenVersion{}) || gotKey != (identity.IdempotencyKey{}) {
				t.Fatal("failed constructor retained request bindings")
			}
		})
	}
	grant, key, err := (sso.RevokeEnterpriseToken{}).Bindings()
	if err != sso.ErrInvalidInput || grant != (sso.TokenVersion{}) || key != (identity.IdempotencyKey{}) {
		t.Fatal("zero request returned usable bindings")
	}
}

func TestRevokeEnterpriseTokenDeniesImplicitDisclosure(t *testing.T) {
	grant, key := enterpriseTokenRevokeInputs(t)
	request, err := sso.NewRevokeEnterpriseToken(grant, key)
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]any{
		"request": request, "pointer": &request, "zero": sso.RevokeEnterpriseToken{},
	} {
		t.Run(name, func(t *testing.T) {
			for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x"} {
				if got := fmt.Sprintf(format, value); got != "sso.RevokeEnterpriseToken(redacted)" {
					t.Fatal("request formatting was not constant and redacted")
				}
			}
			if data, err := json.Marshal(value); !errors.Is(err, sso.ErrSensitiveSerialization) || len(data) != 0 {
				t.Fatal("request JSON serialization admitted")
			}
			text, ok := value.(encoding.TextMarshaler)
			if !ok {
				t.Fatal("request has no text serialization denial")
			}
			if data, err := text.MarshalText(); err != sso.ErrSensitiveSerialization || len(data) != 0 {
				t.Fatal("request text serialization admitted")
			}
			logValue, ok := value.(slog.LogValuer)
			if !ok || logValue.LogValue().Kind() != slog.KindString || logValue.LogValue().String() != "sso.RevokeEnterpriseToken(redacted)" {
				t.Fatal("request structured log value was not constant and redacted")
			}
			var output bytes.Buffer
			slog.New(slog.NewJSONHandler(&output, nil)).Info("revoke", "request", value)
			if !strings.Contains(output.String(), "sso.RevokeEnterpriseToken(redacted)") {
				t.Fatal("structured logger omitted request redaction")
			}
			for _, sentinel := range []string{
				"revoke-tenant-sentinel", "revoke-organization-sentinel", "revoke-provider-sentinel",
				"Revoke.Subject:Exact-é", "AwMDAwMDAwMDAwMDAwMDAw", "Revoke-Retry-Key-Sentinel",
			} {
				if strings.Contains(output.String(), sentinel) {
					t.Fatal("structured logger disclosed a request binding")
				}
			}
		})
	}
}
