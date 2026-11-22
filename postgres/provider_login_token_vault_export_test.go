//go:build integration

package postgres

// Export the actual statements for the existing native-Work measurement harness,
// not a second vault, transaction owner or test-only persistence implementation.
const ProviderLoginTokenOriginalSQLForTest = providerLoginTokenOriginalSQL
const ProviderLoginTokenInsertSQLForTest = providerLoginTokenInsertSQL
