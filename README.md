# TimeFrontiers PHP Session

Secure PHP 8.5 session lifecycle, authenticated identity state, access groups,
CSRF tokens, pull-flash values, bounded session attributes, and optional
location enrichment.

This package stores authentication established by a trusted authentication
service. It does not verify passwords, parse bearer tokens, or decide whether
arbitrary proxy headers are trustworthy.

## Installation

```bash
composer require timefrontiers/php-session:^1.1
```

## Secure bootstrap

Construct `Session` before output. Production configuration defaults to secure,
HttpOnly cookies, SameSite Lax, strict mode, cookie-only IDs, a browser-session
cookie, a 30-minute idle window, and a 24-hour absolute lifetime. The native
handler GC lifetime is configured to cover the absolute authentication window.

```php
use TimeFrontiers\Session;
use TimeFrontiers\SessionConfig;

$config = new SessionConfig(
  cookieName: 'LINKTUDESESSID',
  externalRequestIsSecure: $externalRequestIsSecure,
  cookieSecure: true,
  cookieHttpOnly: true,
  cookieSameSite: 'Lax',
  cookiePath: '/',
  cookieDomain: '.example.com',
);

$session = new Session($logger, $config);
```

`$externalRequestIsSecure` must be computed by the host after applying its
trusted-proxy policy. Session never reads `Forwarded`, `X-Forwarded-*`, or
`$_SERVER['HTTPS']` to grant cookie trust.

For loopback development over HTTP, opt in explicitly:

```php
$session = new Session(
  config: SessionConfig::insecureDevelopment('DEVSESSID')
);
```

An already-active session is adopted only when its name, cookie attributes,
strict mode, cookie-only mode, and trans-SID setting match the supplied
configuration. Otherwise construction throws `SessionException`. Configure and
start Session before sending headers.

## Trusted login identity

`login()` accepts an object with `id` and `uniqueid`. Never pass request JSON,
form data, cookies, or unverified token claims directly.

```php
use TimeFrontiers\AccessGroup;
use TimeFrontiers\AccessRank;

$identity = (object)[
  'id' => 42,
  'uniqueid' => '01234567890',
  'name' => 'Ada',
  'surname' => 'Lovelace',
  'country_code' => 'NG',
  'avatar' => '/avatar/ada.png',
  'auth_version' => 3,
  'access_group' => AccessGroup::ADMIN,
  'access_rank' => AccessRank::ADMIN,
];

if (!$session->login($identity, session_lifetime: 7200)) {
  // The existing guest/authenticated state remains unchanged.
}
```

Login validates the entire projection, rotates the ID with old-state deletion,
and only then commits one versioned payload. A rotation failure cannot leave a
partial login.

CSRF tokens minted before authentication are discarded only after a successful
ID rotation, so a guest token cannot cross into the authenticated privilege
context. Bounded application attributes and pull-flash values intentionally
survive login for compatibility (for example, a return URL or success notice).
Strict mode and ID rotation prevent another client from planting that guest
state.

Group and rank rules are fail-closed:

- if neither is supplied, the identity becomes `USER`;
- if only one is supplied, the other is derived through `php-core`;
- if both are supplied, they must agree;
- guest, negative, unknown, or unsupported future values are rejected;
- a value that is supplied but does not normalize is rejected outright. It is
  never treated as absent, so an unusable `access_group` can never hand the
  privilege decision to `access_rank`.

The default stored identity contains `id`, `uniqueid`, canonical group/rank,
`name`, `surname`, `country_code`, `avatar`, and `auth_version`. Other benign
properties are not retained. Sensitive field names, closures, resources,
unsupported objects, cycles, deep arrays, and oversized values reject login.

`id`, `uniqueid`, group, and rank are credentials and are validated strictly.
The optional display fields `name`, `surname`, `avatar`, and `country_code` are
enrichment: a value that cannot be used is stored as `null` rather than denying
authentication, so a blank surname or an empty country column never locks a
valid identity out. Explicitly configured `identityFields` and `identityMapper`
output remain strict.

An application may explicitly map additional safe scalar identity fields:

```php
$config = new SessionConfig(
  identityMapper: static function (object $source, object $safe): array {
    return ['tenant_code' => ((array) $source)['tenant_code']];
  },
);
```

Mapper output remains subject to the same sensitive-name, field-count, string,
and total-size limits.

## Authentication and access

```php
if ($session->isLoggedIn()) { // loggedIn() is an alias
  $id = $session->id();       // getUserId() is an alias
  $code = $session->name;     // authenticated uniqueid
  $user = $session->user();   // bounded stdClass projection
}

$group = $session->access_group(); // AccessGroup enum
$rank = $session->access_rank();   // scalar rank

if ($session->hasRank(AccessRank::MODERATOR)) {}
if ($session->inGroup(AccessGroup::ADMIN)) {}
if ($session->isStaff()) {}
if ($session->isTechnical()) {}
if ($session->isAdmin()) {}
```

Guest names are random display labels prefixed with `GUEST_`. They are not
security identifiers.

## Expiry

Authentication has an idle expiry and an absolute expiry. `getExpiry()` returns
the earlier timestamp. Equality with the current time is expired.

```php
$expiresAt = $session->getExpiry();
$expired = $session->isExpired();
$extended = $session->extendExpiry(1800);
```

Activity does not automatically slide the idle window in 1.1. Extension must be
explicit, requires authentication, and cannot exceed the configured idle,
extension, or absolute cap. Persistent cookies are reissued when applicable.

## Logout

```php
if (!$session->logout()) {
  // Local state is guest, but cookie or handler cleanup was incomplete.
}
```

Logout resets the local object regardless of external failures, deletes the
cookie with the exact creation attributes, rotates/deletes the old identifier,
checks `session_destroy()`, and reports incomplete cleanup as `false`.

## CSRF protection

Each form/action may hold several one-time tokens, so separate browser tabs do
not invalidate each other.

```php
$token = $session->generateCSRFToken('profile-form', 1500);

if (!$session->validateCSRFToken('profile-form', $submittedToken)) {
  // Wrong submissions do not consume other valid tokens.
}

echo $session->csrfField('profile-form', 'csrf_token');
```

Tokens are cryptographically random, stored as hashes, compared against every
candidate in constant time, and consumed only after a successful match. Form
IDs, TTL, tokens per form, and total tokens are bounded. Expired and malformed
entries are pruned. A successful login invalidates every token minted before
authentication; generate fresh tokens for authenticated forms.

`createCSRFtoken()` and `isValidCSRFtoken()` remain callable for 1.x compatibility
but emit `E_USER_DEPRECATED`.

## Bounded attributes and flash

```php
$session->set('theme', ['mode' => 'dark']);
$theme = $session->get('theme', ['mode' => 'light']);
$exists = $session->has('theme');
$all = $session->all();
$session->remove('theme');

$session->flash('success', 'Saved');
$message = $session->getFlash('success'); // reads and removes
```

Mutable attributes are stored separately from canonical identity and merged
into the `user()` stdClass while authenticated. `id`, `uniqueid`, identity
fields, group, and rank cannot be changed through `set()` or `remove()`.

Attributes and flash accept bounded scalars and arrays. Sensitive keys,
closures, resources, unsupported objects, recursion, excessive depth/items,
invalid UTF-8, non-finite floats, and oversized values are rejected with
`InvalidArgumentException`. A stored null counts as present.

Note the deliberate asymmetry: `login()` reports failure by returning `false`,
while `set()` and `flash()` throw. Storage rejection is a programming error in
the caller, not an authentication outcome.

Session stores all of its state under one namespaced `$_SESSION` root key.
Other root keys belong to the application and are never read. The v1.0 keys
(`user`, `name`, `_expire`, `access_group`, `access_rank`, `location`) are swept
exactly once, when a session is first upgraded to the 1.1 storage layout; after
that the application may use those names freely without affecting the session.

Flash uses pull-until-read semantics: it remains available until `getFlash()`
consumes it. It is not automatically aged after one request.

## Optional location enrichment

Location is disabled by default and never runs during login.

```php
$config = new SessionConfig(locationEnabled: true);
$session = new Session(config: $config);
$session->refreshLocation();
$location = $session->location();
```

When enabled without a resolver, `refreshLocation()` uses
`timefrontiers/php-location` if installed. A trusted resolver may instead be
provided through `locationResolver`. Optional failure returns `false` without a
session error; `locationRequired: true` adds a stable error but still cannot
change login or access rank.

## Errors and logging

Errors are instance-owned canonical tuples:

```text
[minimum_rank, code, message, redacted_origin, redacted_line]
```

```php
if ($session->hasErrors()) {
  $errors = $session->getErrors();
}

$session->clearInstanceErrors('login'); // this instance/context only
$session->clearInstanceErrors();        // all errors on this instance
Session::clearErrors();                  // compatibility: all live instances
```

`errorCount()`, `firstError()`, and `errorMessages()` from the underlying trait
are intentionally not part of Session's public v1.1 API. Use `getErrors()` or an
optional `InstanceError` presenter.

Raw exception messages, provider payloads, paths, and request/session values are
never copied into tuples. Original throwables are sent only to the configured
PSR-3 logger. `timefrontiers/php-instance-error` is optional for rank-filtered
presentation.

## Validation

```bash
composer validate --strict
composer check
```

The test suite includes deterministic failure injection, isolated native PHP
session-handler tests, and a loopback HTTP test proving that login rotates the
cookie and the pre-login ID cannot restore authentication.
