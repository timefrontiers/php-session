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
echo $session->name;           // "john.doe"
echo $session->access_rank;    // 4 (MODERATOR)
echo $session->access_group;   // AccessGroup::MODERATOR
```

## Authentication

### Login

```php
// User object from your database
$user = (object)[
  'id'           => 123,
  'name'         => 'john.doe',
  'access_group' => AccessGroup::MODERATOR,
  'access_rank'  => AccessRank::MODERATOR,
];

// Login with 30-minute session
$session->login($user);

// Login with "remember me" cookie
$session->login($user, remember: true);

// Custom session lifetime (2 hours)
$session->login($user, session_lifetime: 7200);
```

### Logout

```php
$session->logout();
```

### Check Authentication

```php
if ($session->isLoggedIn()) {
  $userId = $session->getUserId();  // or $session->id()
  $name = $session->name;
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

// Direct access
if ($session->access_rank >= AccessRank::DEVELOPER->value) {
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

Tokens are single-use and automatically expire (default: 1 hour).

## Session Storage

```php
// Store data
$session->set('cart', ['item1', 'item2']);

// Retrieve data
$cart = $session->get('cart', []);  // Default: []

// Check existence
if ($session->has('cart')) { }

// Remove
$session->remove('cart');

// Get all session data
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
if ($session->location) {
  echo $session->location->country;      // "United States"
  echo $session->location->country_code; // "US"
  echo $session->location->city;         // "San Francisco"
  echo $session->location->currency_code;// "USD"
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
- Timing-safe token comparison (hash_equals)
- Single-use CSRF tokens

## Dependencies

- `psr/log` - For PSR-3 logger interface
- `timefrontiers/php-core` - For AccessRank and AccessGroup enums
- `timefrontiers/php-instance-error` - For error extraction

## Optional Dependencies

- `timefrontiers/php-location` - For IP geolocation

## License

MIT
