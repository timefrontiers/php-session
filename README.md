# TimeFrontiers PHP Session

A modern, secure PHP session manager with authentication state, access control, CSRF protection, and geolocation.

[![PHP Version](https://img.shields.io/badge/php-%3E%3D8.1-8892BF.svg)](https://php.net/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## Features

- **Secure session handling** with HttpOnly, Secure, and SameSite cookie flags.
- **User authentication state** with configurable session lifetime and "remember me" functionality.
- **Access control** using `AccessGroup` and `AccessRank` enums (10 predefined levels).
- **CSRF token generation and validation** using cryptographically secure random bytes.
- **Server-side geolocation** (via `timefrontiers/php-location`).
- **PSR-3 logging support** for debugging and monitoring.
- **Internal error collection** with access-based filtering via the `InstanceError` package.
- **Backward compatibility** for legacy CSRF methods.

## Installation

```bash
composer require timefrontiers/php-session
```

## Requirements

- PHP 8.1 or higher
- [timefrontiers/php-location](https://github.com/timefrontiers/php-location) ^2.0
- [timefrontiers/php-instance-error](https://github.com/timefrontiers/php-instance-error) ^1.0
- [psr/log](https://github.com/php-fig/log) ^3.0 (optional but recommended)

## Basic Usage

### Initialization

```php
use TimeFrontiers\Session;

$session = new Session();
// Or with a PSR-3 logger
$session = new Session($logger);
```

### Login

```php
// $user must be an object with at least 'id' and a public identifier ('name' or 'uniqueid')
$user = getUserFromDatabase($credentials);
$user->access_group = 'ADMIN'; // optional
$user->access_rank = 6;        // optional

if ($session->login($user, remember: true, session_lifetime: 3600)) {
    echo "Welcome, {$session->name}!";
} else {
    // Handle failure – use InstanceError to retrieve errors
    $errors = (new \TimeFrontiers\InstanceError($session, false))->get('login');
    foreach ($errors as $error) {
        echo $error[2]; // message
    }
}
```

### Check Login State

```php
if ($session->isLoggedIn()) {
    $userId = $session->getUserId();
    $group = $session->access_group;   // AccessGroup enum
    $rank = $session->access_rank;     // int
}
```

### Logout

```php
$session->logout();
```

### CSRF Protection

```php
// In your form
$token = $session->generateCSRFToken('login_form');
echo '<input type="hidden" name="csrf_token" value="' . $token . '">';

// Validate submission
if (!$session->validateCSRFToken('login_form', $_POST['csrf_token'])) {
    die('Invalid CSRF token');
}
```

### Location

```php
// Refresh user's location from server IP
$session->refreshLocation();
echo $session->location->city;
```

### Storing Arbitrary Data

```php
$session->set('cart', ['item1', 'item2']);
$cart = $session->get('cart', []);
$session->remove('cart');
```

## Access Control Enums

The package includes two enums for managing permissions:

### `AccessGroup` (string-backed)

```php
enum AccessGroup: string {
    case GUEST = 'GUEST';
    case USER = 'USER';
    case ANALYST = 'ANALYST';
    case ADVERTISER = 'ADVERTISER';
    case MODERATOR = 'MODERATOR';
    case EDITOR = 'EDITOR';
    case ADMIN = 'ADMIN';
    case DEVELOPER = 'DEVELOPER';
    case SUPERADMIN = 'SUPERADMIN';
    case OWNER = 'OWNER';
}
```

### `AccessRank` (int-backed)

```php
enum AccessRank: int {
    case GUEST = 0;
    case USER = 1;
    case ANALYST = 2;
    case ADVERTISER = 3;
    case MODERATOR = 4;
    case EDITOR = 5;
    case ADMIN = 6;
    case DEVELOPER = 7;
    case SUPERADMIN = 8;
    case OWNER = 14;
}
```

Higher rank values indicate greater privileges.

## Error Handling

Errors are stored internally in a protected `$_errors` property and can be retrieved via the `getErrors()` method. The `InstanceError` class (provided by `timefrontiers/php-instance-error`) automatically calls `$session->getErrors()` and filters the results based on the current user's `access_rank`.

```php
use TimeFrontiers\InstanceError;

// After a failed operation
if (!$session->login($user)) {
    // Get errors for a specific context
    $errors = (new InstanceError($session, false))->get('login');
    // Or all errors
    $all_errors = (new InstanceError($session, false))->get();
}
```

The error array format is: `[$min_rank, $code, $message, $file, $line]`.  
Only errors where the user's `access_rank` is greater than or equal to `$min_rank` are shown.

## Backward Compatibility

If you are migrating from the legacy `TymFrontiers\Session` class, the following deprecated CSRF methods are still available (but trigger deprecation notices):

| Old API                            | New API                                    |
|------------------------------------|--------------------------------------------|
| `$session->createCSRFtoken()`      | `$session->generateCSRFToken()`            |
| `$session->isValidCSRFtoken()`     | `$session->validateCSRFToken()`            |

It is **strongly recommended** to update your code to the new API for better security and future compatibility.

## Security Considerations

- **Always use HTTPS** in production to ensure session cookies are transmitted securely.
- **Regenerate session IDs** at login/logout (handled automatically).
- **CSRF tokens are one-time use** and removed after validation.
- **Location data is obtained server-side** from IP address only; client-side cookies are ignored.
- **User object is not stored in session** by default – only the user ID. Fetch full user data from your database as needed.

## License

MIT License. See [LICENSE](LICENSE) for details.
