//go:build integration

package postgres

import database "github.com/faustbrian/go-postgres"

const ProviderSAMLCallbackDispositionSQLForTest = providerSAMLLoginCallbackDispositionFenceSQL
const CompleteProviderSAMLCallbackSQLForTest = completeProviderSAMLLoginCallbackSQL
const SAMLReplayCommandExistsSQLForTest = samlReplayCommandExistsSQL

// Replace only the same-primary diagnostic connection. All policy, verifier,
// repositories and original browser/callback bindings remain the real fixture's.
func ProviderSAMLCallbackWithPoolForTest(service *ProviderSAMLLoginCompletionService, pool *database.Pool) *ProviderSAMLLoginCompletionService {
	router := *service.start.router
	router.pool = pool
	start := *service.start
	start.router = &router
	completion := *service
	completion.start = &start
	return &completion
}
