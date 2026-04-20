# TimeFrontiers PHP Session

Modern PHP session manager with authentication state, access control, CSRF protection, and geolocation.

## Installation

```bash
composer require timefrontiers/php-session
```

## Features

- Secure session handling with HTTPOnly, SameSite cookies
- User authentication state management
- Access rank/group based authorization
- CSRF token generation and validation
- Flash messages
- IP geolocation integration
- PSR-3 logger support

## Quick Start

```php
use TimeFrontiers\Session;
use TimeFrontiers\AccessRank;

// Start session
$session = new Session();

// Check if logged in
if (!$session->isLoggedIn()) {
  // Show login form
}

// Access user info
echo $session->id();           // e.g. 1
echo $session->name();         // uniqueid e.g. "01234567890"
echo $session->access_rank();  // 4 (MODERATOR)
echo $session->access_group(); // AccessGroup::MODERATOR

// Full user object
$user = $session->user();
echo $user->surname;

// Geolocation
$loc = $session->location();
echo $loc?->country;
```

## Authentication

### Login

```php
// User object from your database — must have 'id' and 'uniqueid'
$user = (object)[
  'id'           => 123,
  'uniqueid'     => '01234567890',
  'name'         => 'John',
  'surname'      => 'Doe',
  'access_group' => AccessGroup::MODERATOR,
  'access_rank'  => AccessRank::MODERATOR,
];

// Login with 30-minute session (default)
$session->login($user);

// Custom session lifetime (2 hours)
$session->login($user, session_lifetime: 7200);
```

> **Note:** "Remember me" / persistent login requires storing a token in your database and is intentionally left to the application layer.

### Logout

```php
$session->logout();
```

### Check Authentication

```php
if ($session->isLoggedIn()) {
  $userId = $session->getUserId();  // or $session->id()
  $name   = $session->name();       // uniqueid of logged-in user
  $user   = $session->user();       // full user object
}
```

## Access Control

```php
use TimeFrontiers\AccessRank;

// Check rank
if ($session->hasRank(AccessRank::MODERATOR)) {
  // Can moderate
}

// Check group
if ($session->inGroup(AccessGroup::ADMIN)) {
  // Is admin
}

// Convenience methods
if ($session->isStaff()) { }     // MODERATOR or higher
if ($session->isTechnical()) { } // DEVELOPER or higher
if ($session->isAdmin()) { }     // ADMIN or higher

// Via getters
if ($session->access_rank() >= AccessRank::DEVELOPER->value) {
  // Show debug info
}
```

## CSRF Protection

### Generate Token

```php
// In your form
$token = $session->generateCSRFToken('contact_form');
```

```html
<form method="post">
  <input type="hidden" name="_csrf_token" value="<?= $token ?>">
  <!-- form fields -->
</form>
```

Or use the helper:

```php
echo $session->csrfField('contact_form');
// Outputs: <input type="hidden" name="_csrf_token" value="...">
```

### Validate Token

```php
if (!$session->validateCSRFToken('contact_form', $_POST['_csrf_token'])) {
  die('Invalid CSRF token');
}
```

Tokens are single-use and automatically expire (default: 1 hour). Expired tokens from other forms are pruned automatically on each `generateCSRFToken()` call.

## User Object Storage

`set()`, `get()`, `has()`, and `remove()` operate on the authenticated user object and are persisted to the session. Use these to attach extra data to the user mid-session.

```php
// Store data on the user object
$session->set('theme', 'dark');

// Retrieve
$theme = $session->get('theme', 'light');  // Default: 'light'

// Check existence
if ($session->has('theme')) { }

// Remove
$session->remove('theme');

// Get all user object properties as array
$all = $session->all();
```

## Flash Messages

Flash messages persist for one request only.

```php
// Set flash message
$session->flash('success', 'Profile updated!');

// Redirect...

// Get and remove flash message
if ($session->hasFlash('success')) {
  echo $session->getFlash('success');
}
```

## Session Expiry

```php
// Get expiration timestamp
$expires = $session->getExpiry();

// Check if expired
if ($session->isExpired()) {
  // Re-authenticate
}

// Extend session by 30 minutes
$session->extendExpiry(1800);
```

## Geolocation

Requires `timefrontiers/php-location`:

```php
// Refresh location from IP
$session->refreshLocation();

// Access location data
$loc = $session->location();
if ($loc) {
  echo $loc->country;       // "United States"
  echo $loc->country_code;  // "US"
  echo $loc->city;          // "San Francisco"
  echo $loc->currency_code; // "USD"
}
```

## Logging

Pass a PSR-3 logger for session events:

```php
use Monolog\Logger;
use Monolog\Handler\StreamHandler;

$logger = new Logger('session');
$logger->pushHandler(new StreamHandler('session.log'));

$session = new Session($logger);
```

## Error Handling

Session uses static error collection for compatibility with InstanceError:

```php
use TimeFrontiers\InstanceError;

$session->login($invalidUser);

if ($session->hasErrors()) {
  $extractor = new InstanceError($session);
  $errors = $extractor->get('login');

  foreach ($errors as $err) {
    echo $err[2]; // Error message
  }
}

// Clear errors
Session::clearErrors();
```

## Security Features

- Session ID regeneration on login (prevents fixation)
- Secure cookies (HTTPOnly, SameSite=Lax)
- HTTPS-only cookies when available
- Timing-safe CSRF token comparison (`hash_equals`)
- Single-use CSRF tokens with automatic expiry pruning
- No session ID regeneration on every request (prevents concurrency issues)

## Dependencies

- `psr/log` - For PSR-3 logger interface
- `timefrontiers/php-core` - For AccessRank and AccessGroup enums
- `timefrontiers/php-instance-error` - For error extraction

## Optional Dependencies

- `timefrontiers/php-location` - For IP geolocation

## License

MIT
