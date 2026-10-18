# Pocket ID Auth Fixtures

These are synthetic claim and discovery-document shapes, not captured production
tokens or a claim of live Pocket ID interoperability. Tests sign fresh RS256 JWTs
with an ephemeral test key and relative expiry times. No private signing key or
usable provider credential is checked in.

The fixtures exercise resource-bound user and M2M access, client-bound ID token
rejection, scope mapping, issuer/audience checks, and expiry through snulbug's
existing OAuth validator. API permissions need not appear in the issuer's global
`scopes_supported` metadata; actual token grants are tested separately.

Provider references:

- https://pocket-id.org/docs/guides/apis
- https://pocket-id.org/docs/guides/scopes-and-claims
- https://pocket-id.org/docs/guides/client-id-metadata-documents

The live passkey/client login flow is outside this fixture suite.
