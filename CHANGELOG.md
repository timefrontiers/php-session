# Changelog

All notable changes to this project are documented here.

## [1.1.0] - 2026-08-09

### Added

- Immutable `SessionConfig` with explicit cookie, request-security, lifetime,
  CSRF, identity, storage, and location policy.
- Secure production defaults and an explicit insecure-development factory.
- Versioned authentication payloads with idle and absolute expiry.
- Bounded identity mapping and serialization-safe attribute/flash storage.
- Multi-tab CSRF token lists with per-form/global caps and consume-on-match.
- Direct `timefrontiers/php-has-errors` integration with instance-isolated
  canonical error tuples.
- Per-instance and per-context error clearing through `clearInstanceErrors()`;
  the static compatibility clear remains available.
- Native-handler and real HTTP session-rotation integration tests.

### Changed

- PHP now requires 8.5.
- Login rotates the session ID before committing authentication and deletes the
  old handler state.
- Group and rank are strictly reconciled through `php-core`; malformed values
  fail closed.
- Restoration revalidates the complete payload and rotates malformed or expired
  authentication back to guest.
- Logout checks rotation, matching cookie deletion, and handler destruction.
- `extendExpiry()` requires authentication and respects configured idle and
  absolute caps.
- Location enrichment is explicit and no longer runs inside login.
- Flash behavior is documented as pull-until-read.
- Stored null values count as present.
- The v1.0 key sweep is a one-time migration recorded in the storage layout.
  Application-owned `$_SESSION` root keys no longer clear an active login.
- Unusable values for the optional display fields `name`, `surname`, `avatar`,
  and `country_code` are stored as `null` instead of failing authentication.
  Credential fields remain strict.
- Oversized restored guest storage is discarded and reported as a session error
  instead of throwing out of the constructor.

### Deprecated

- `createCSRFtoken()` in favor of `generateCSRFToken()`.
- `isValidCSRFtoken()` in favor of `validateCSRFToken()`.

### Security

- Prevented session fixation across authentication and privilege boundaries.
- Prevented inconsistent or tampered access rank restoration.
- Prevented privilege escalation through a supplied but unusable `access_group`:
  a present-and-invalid group or rank is rejected outright and never derived
  from the other field.
- Prevented arbitrary object, secret, closure, resource, cyclic, deep, and
  oversized session serialization.
- Removed request/proxy-header inference from secure-cookie decisions.
- Wrong CSRF submissions no longer consume valid tokens.
- Successful login discards tokens minted in the guest privilege context.
- Raw throwable details are no longer exposed through package errors.

### Dependencies

- Added `timefrontiers/php-has-errors:^1.0` as a runtime dependency.
- Moved `timefrontiers/php-instance-error` to `suggest`.
