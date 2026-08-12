# Upgrading to 1.1

## Platform

Version 1.1 requires PHP 8.5. Upgrade `timefrontiers/php-core` and
`timefrontiers/php-has-errors` with this package.

## Existing authenticated sessions are invalidated

Version 1.1 intentionally does not migrate the loose v1.0 keys (`user`, `name`,
`_expire`, `access_group`, `access_rank`, and `location`). On first access they
are cleared, the session ID is rotated where safe, and the user must
authenticate again.

Deploy this as a coordinated authentication release and notify applications
that active users will be signed out.

The sweep runs **once per session**, and the 1.1 storage layout then records
that it has happened. Afterwards those six names are ordinary application keys:
writing `$_SESSION['name']` or `$_SESSION['location']` for your own purposes
does not clear the login. All session state lives under one namespaced root key,
so applications should still avoid reading or writing it directly.

## Configure before output

Production defaults to a secure cookie and assumes the trusted host determined
that the external request is HTTPS.

```php
$config = new SessionConfig(
  cookieName: 'LINKTUDESESSID',
  externalRequestIsSecure: $trustedHostResult,
  cookieSecure: true,
  cookieDomain: '.example.com',
);
$session = new Session($logger, $config);
```

Do not pass `Forwarded` or `X-Forwarded-Proto` directly. Resolve proxy trust in
the host and pass only the resulting boolean. Construct Session before output.
An incompatible already-active session now throws instead of emitting warnings.

Use `SessionConfig::insecureDevelopment()` only for local HTTP development.

## Pass a bounded trusted login projection

Continue calling:

```php
$session->login($login, $lifetimeSeconds);
```

The object must contain valid `id` and `uniqueid`. Do not pass an entire database
model, request object, provider response, or unverified token claims.

Default retained fields are `name`, `surname`, `country_code`, `avatar`, and
`auth_version`. Configure `identityMapper` for other explicitly approved scalar
fields. Objects containing sensitive names or unsupported values now fail login
instead of silently persisting dangerous state.

Unusable values for the optional display fields `name`, `surname`, `avatar`, and
`country_code` are stored as `null` instead of failing the login. Consumers that
render these must handle `null`. `id`, `uniqueid`, group, and rank stay strict.

If access group and rank are both present, they must agree. Update projections
that previously supplied a high rank with a different group. Missing privilege
still defaults to `USER` for compatibility.

A privilege value that is *present but unusable* — an unknown group string, an
empty string, or an explicit `null` — is now rejected rather than derived from
the other field. Projections that set `access_group = null` alongside a numeric
`access_rank` previously authenticated at the rank's group and now fail. Omit
the key entirely if you want it derived.

`set()` and `flash()` throw on rejection while `login()` returns `false`. Remove
any `set()` call that stores a whole model object; `user()` already exposes the
committed projection.

## Session identifiers now rotate

Successful login always runs `session_regenerate_id(true)` before committing
identity. Logout rotates/deletes handler state and deletes the cookie with the
same attributes used at creation. Ensure custom session handlers correctly
support regeneration and destruction.

Login returns `false` when rotation fails and leaves the previous state intact.
Logout returns `false` when cookie or handler cleanup is incomplete, although
the local object is always reset to guest.

## Expiry model

Authentication now has idle and absolute expiry. The default idle window is 30
minutes and the default absolute lifetime is 24 hours. Activity does not slide
the idle window automatically. Call `extendExpiry()` explicitly; it now requires
authentication and is capped by configuration.

Expiry equality is expired. Code relying on an extra equality second must be
updated.

## CSRF behavior

Multiple valid tokens may coexist for one form ID. A wrong token no longer
consumes valid tokens. A successful match remains single-use.

Successful login discards all tokens minted before authentication. Generate a
new token after login before rendering or retrying an authenticated form.
Bounded application attributes and pull-flash values continue across login.

Form IDs and TTLs are validated and capped. Replace unbounded/dynamic form IDs
and TTLs longer than the configured maximum. The mixed-case aliases still work
but emit deprecations; migrate to `generateCSRFToken()` and
`validateCSRFToken()`.

## Key/value and flash values

`set()` and `flash()` now reject sensitive keys and unsafe, cyclic, deep, or
oversized values with `InvalidArgumentException`. Authentication fields cannot
be changed using `set()` or `remove()`.

Stored null now counts as present. Flash is pull-until-read, not automatically
aged at the end of a request.

## Location

Login no longer performs synchronous location work. Enable location explicitly
and call `refreshLocation()` after authentication or from application-controlled
enrichment work. Missing optional support is not a session error.

## Errors

`getErrors()`, `hasErrors()`, and static `clearErrors()` remain callable. Error
storage is now instance-owned and uses canonical five-element tuples from
`php-has-errors`. Use additive `clearInstanceErrors($context)` to clear one
instance or one operation; the static compatibility method still clears every
live Session instance. `php-instance-error` is optional and should be retained
by applications only when rank-filtered presentation is needed.

The underlying trait's `errorCount()`, `firstError()`, and `errorMessages()`
helpers are deliberately private on Session in 1.1 and are not compatibility
API.

Do not depend on raw exception messages, file paths, or line numbers from
Session errors. These are deliberately redacted; inspect the trusted PSR-3 log.

## Consumer verification

- Use `access_group()` and `access_rank()` rather than protected properties.
- Confirm `user()` consumers use only approved retained fields.
- Confirm authentication handlers treat `login() === false` as no new login.
- Confirm logout callers handle incomplete cleanup.
- Run an HTTP test proving that the guest cookie changes on login and the old ID
  cannot restore authentication.

Before release:

```bash
composer validate --strict
composer check
```
