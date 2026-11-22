package postgres

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

func TestProviderLoginCallbackDispositionRequiresExactOriginalScope(t *testing.T) {
	_, input, now, _ := providerLoginPayloadFixture(t)
	callback, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	found := providerLoginCallbackLookup{Row: input.rowIdentity(), ObservedAt: *now,
		Binding: providerLoginStoredBinding{Metadata: providerLoginBindingMetadata{Input: input, CallbackCommand: callback}}}
	binding := input.Command
	binding.CommandID = callback
	binding.OperationID, binding.SchemaID = "identity.sso.oidc-callback", "sso-enterprise-oidc-callback-v1"
	deadline := now.Add(10 * time.Second)
	if !validProviderLoginCallbackDispositionScope(binding, found, deadline) {
		t.Fatal("exact callback scope was denied")
	}
	for _, tc := range []struct {
		name   string
		change func(*identity.CommandBinding, *providerLoginCallbackLookup, *time.Time)
	}{
		{"foreign tenant", func(b *identity.CommandBinding, _ *providerLoginCallbackLookup, _ *time.Time) { b.TenantID = "foreign" }},
		{"wrong callback command", func(b *identity.CommandBinding, _ *providerLoginCallbackLookup, _ *time.Time) {
			b.CommandID = input.Command.CommandID
		}},
		{"wrong operation", func(b *identity.CommandBinding, _ *providerLoginCallbackLookup, _ *time.Time) {
			b.OperationID = "identity.oauth.callback"
		}},
		{"wrong schema", func(b *identity.CommandBinding, _ *providerLoginCallbackLookup, _ *time.Time) {
			b.SchemaID = "oauth-signin-callback-v1"
		}},
		{"wrong original start", func(b *identity.CommandBinding, _ *providerLoginCallbackLookup, _ *time.Time) {
			b.RecordID = string(callback)
		}},
		{"wrong browser flow", func(b *identity.CommandBinding, _ *providerLoginCallbackLookup, _ *time.Time) {
			b.AnonymousFlowID = string(callback)
		}},
		{"wrong actor", func(b *identity.CommandBinding, _ *providerLoginCallbackLookup, _ *time.Time) { b.ActorID = "foreign" }},
		{"selected user", func(b *identity.CommandBinding, _ *providerLoginCallbackLookup, _ *time.Time) { b.UserID = "user" }},
		{"organization drift", func(_ *identity.CommandBinding, f *providerLoginCallbackLookup, _ *time.Time) {
			f.Row.OrganizationID = "foreign"
		}},
		{"provider drift", func(_ *identity.CommandBinding, f *providerLoginCallbackLookup, _ *time.Time) {
			f.Row.ProviderID = "foreign"
		}},
		{"version drift", func(_ *identity.CommandBinding, f *providerLoginCallbackLookup, _ *time.Time) {
			f.Row.ProviderVersion++
		}},
		{"mapping drift", func(_ *identity.CommandBinding, f *providerLoginCallbackLookup, _ *time.Time) { f.Row.MappingVersion++ }},
		{"credential drift", func(_ *identity.CommandBinding, f *providerLoginCallbackLookup, _ *time.Time) {
			f.Row.CredentialGeneration++
		}},
		{"terminal", func(_ *identity.CommandBinding, f *providerLoginCallbackLookup, _ *time.Time) { f.CompletedAt = now }},
		{"zero observation", func(_ *identity.CommandBinding, f *providerLoginCallbackLookup, _ *time.Time) {
			f.ObservedAt = time.Time{}
		}},
		{"zero deadline", func(_ *identity.CommandBinding, _ *providerLoginCallbackLookup, d *time.Time) { *d = time.Time{} }},
		{"expired deadline", func(_ *identity.CommandBinding, _ *providerLoginCallbackLookup, d *time.Time) { *d = *now }},
		{"renewed freshness", func(_ *identity.CommandBinding, _ *providerLoginCallbackLookup, d *time.Time) {
			*d = now.Add(21 * time.Second)
		}},
		{"renewed transaction", func(_ *identity.CommandBinding, _ *providerLoginCallbackLookup, d *time.Time) {
			*d = input.ExpiresAt.Add(time.Second)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, f, d := binding, found, deadline
			tc.change(&b, &f, &d)
			if validProviderLoginCallbackDispositionScope(b, f, d) {
				t.Fatal("mismatched callback scope was admitted")
			}
		})
	}
}

func TestProviderLoginCallbackDispositionRequiresNativeDisableBinding(t *testing.T) {
	_, input, _, _ := providerLoginPayloadFixture(t)
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	binding := identity.CommandBinding{CommandID: id, TenantID: input.Command.TenantID, UserID: "owner", ActorID: "owner",
		ActorKind: authorization.SubjectUser, OperationID: "identity.sso.provider.disable", PolicyID: "policy", PolicyVersion: 1,
		SchemaID: "sso-static-oidc-disable-v1", SchemaVersion: 1, CorrelationID: string(id), RecordID: input.ProviderID}
	check := func(b identity.CommandBinding, command string) bool {
		wire, err := json.Marshal(providerStoredBinding(b))
		if err != nil {
			t.Fatal(err)
		}
		return validProviderLoginCallbackDisableBinding(input.rowIdentity(), command, wire)
	}
	if !check(binding, string(id)) {
		t.Fatal("exact native disable command was denied")
	}
	for _, change := range []func(*identity.CommandBinding){
		func(b *identity.CommandBinding) { b.TenantID = "foreign" },
		func(b *identity.CommandBinding) { b.RecordID = "foreign" },
		func(b *identity.CommandBinding) { b.OperationID = "identity.sso.provider.enable" },
		func(b *identity.CommandBinding) { b.SchemaID = "sso-static-oidc-enable-v1" },
		func(b *identity.CommandBinding) { b.UserID = "" },
		func(b *identity.CommandBinding) { b.ActorID = "foreign" },
	} {
		b := binding
		change(&b)
		if check(b, string(id)) {
			t.Fatal("mismatched native disable command was admitted")
		}
	}
	if check(binding, string(input.Command.CommandID)) || validProviderLoginCallbackDisableBinding(input.rowIdentity(), string(id), []byte("invalid")) {
		t.Fatal("missing or substituted native command was admitted")
	}
}
