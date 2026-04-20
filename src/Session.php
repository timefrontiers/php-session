<?php

declare(strict_types=1);

namespace TimeFrontiers;

use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * Manages PHP session, user authentication state, CSRF tokens, and geolocation.
 *
 * Errors are collected in the static $_errors array and can be retrieved
 * using the InstanceError class.
 *
 * @example
 * ```php
 * // Start session
 * $session = new Session();
 *
 * // Check login state
 * if (!$session->isLoggedIn()) {
 *   $session->login($user);
 * }
 *
 * // Access id and name (uniqueid)
 * echo $session->id();   // e.g. 1
 * echo $session->name;   // e.g. 01234567890
 *
 * // Full user object
 * $user = $session->user();
 * echo $user->surname;
 *
 * // Access control via getters
 * if ($session->access_rank() >= AccessRank::MODERATOR->value) {
 *   // Show admin panel
 * }
 *
 * // Store/retrieve data on the user object
 * $session->set('theme', 'dark');
 * $theme = $session->get('theme');
 *
 * // CSRF protection
 * $token = $session->generateCSRFToken('contact_form');
 * if (!$session->validateCSRFToken('contact_form', $_POST['token'])) {
 *   die('Invalid token');
 * }
 * ```
 */
final class Session {

  private bool $_logged_in = false;
  private int $_expire = 0;
  private int|string|null $_id = null;
  private ?LoggerInterface $_logger;

  /**
   * @var string The user's public unique identifier (uniqueid).
   */
  public string $name = '';

  /**
   * @var object|null The user's geolocation information.
   */
  protected ?object $_location = null;

  /**
   * @var object|null The full authenticated user object.
   */
  protected ?object $_user = null;

  /**
   * @var AccessGroup The user's access group.
   */
  protected AccessGroup $_access_group;

  /**
   * @var int The user's access rank (value from AccessRank enum).
   */
  protected int $_access_rank;

  /**
   * @var array Static error collection.
   *            Format: ['context' => [[min_rank, code, message, file, line], ...]]
   */
  protected static array $_errors = [];

  /**
   * @param LoggerInterface|null $logger PSR-3 logger for internal logging.
   * @throws SessionException If session cannot be started.
   */
  public function __construct(?LoggerInterface $logger = null) {
    $this->_logger = $logger ?? new NullLogger();
    $this->_configureSessionCookie();

    if (\session_status() === PHP_SESSION_NONE) {
      if (!\session_start()) {
        throw new SessionException('Failed to start session.');
      }
    }

    $this->_checkLogin();

    // Set defaults for guest users
    if (!$this->_logged_in) {
      $this->_access_group = AccessGroup::GUEST;
      $this->_access_rank  = AccessRank::GUEST->value;
      $this->name         = 'GUEST_' . \time();
    }
  }

  // =========================================================================
  // Authentication State
  // =========================================================================

  /**
   * Checks if a user is currently logged in.
   */
  public function isLoggedIn():bool {
    return $this->_logged_in;
  }

  /**
   * Alias for isLoggedIn().
   */
  public function loggedIn():bool {
    return $this->_logged_in;
  }

  /**
   * Returns the internal database ID of the logged-in user, or null if guest.
   */
  public function getUserId():int|string|null {
    return $this->_id;
  }

  /**
   * Alias for getUserId() - returns user ID.
   */
  public function id():int|string|null {
    return $this->_id;
  }

  // =========================================================================
  // Getters
  // =========================================================================

  /**
   * Returns the full user object, or null if not logged in.
   */
  public function user():?object {
    return $this->_user;
  }

  /**
   * Returns the user's geolocation information, or null if unavailable.
   */
  public function location():?object {
    return $this->_location;
  }

  /**
   * Returns the user's access group.
   */
  public function access_group():AccessGroup {
    return $this->_access_group;
  }

  /**
   * Returns the user's access rank value.
   */
  public function access_rank():int {
    return $this->_access_rank;
  }

  // =========================================================================
  // Login / Logout
  // =========================================================================

  /**
   * Logs in a user.
   *
   * @param object $user User object with at least 'id' and 'uniqueid'. May also
   *                     contain 'access_group' and 'access_rank'.
   * @param int $session_lifetime Session lifetime in seconds (default 1800 = 30 minutes).
   *                             Values ≤ 0 are ignored and the default is used instead
   *                             (backward-compatible with old API that passed 0 for "no remember-me").
   * @return bool True on success, false on failure (errors in self::$_errors).
   */
  public function login(object $user, int $session_lifetime = 1800):bool {
    // Clear any errors from a previous login attempt
    unset(self::$_errors['login']);

    // Guard against zero or negative lifetime (old API passed 0 for "no remember-me").
    // Treat any value ≤ 0 as the default 30-minute lifetime.
    if ($session_lifetime <= 0) {
      $session_lifetime = 1800;
    }

    if (!\property_exists($user, 'id')) {
      self::_addError(
        'login',
        256,
        'User object must have an "id" property.',
        __FILE__,
        __LINE__,
        AccessRank::DEVELOPER->value
      );
      return false;
    }

    if (!\property_exists($user, 'uniqueid') || $user->uniqueid === null) {
      self::_addError(
        'login',
        256,
        'User object must have a "uniqueid" property.',
        __FILE__,
        __LINE__,
        AccessRank::DEVELOPER->value
      );
      return false;
    }

    try {
      // Store a serialization-safe copy of the user object.
      // _sanitizeUser() converts enum values to their scalar backing values
      // and strips anything non-serializable, producing a plain stdClass that
      // PHP can deserialize on the next request without needing any class loaded.
      $safe_user        = $this->_sanitizeUser($user);
      $this->_user      = $safe_user;
      $_SESSION['user'] = $safe_user;

      $this->_id        = $user->id;
      $this->name      = (string)$user->uniqueid;
      $_SESSION['name'] = $this->name;

      // Set access group and rank
      $group = $this->_normalizeAccessGroup($user->access_group ?? null);
      $rank  = $this->_normalizeAccessRank($user->access_rank ?? null);

      $this->_access_group      = $group;
      $this->_access_rank       = $rank;
      $_SESSION['access_group'] = $group->value;
      $_SESSION['access_rank']  = $rank;

      // Set expiration
      $this->_expire       = \time() + $session_lifetime;
      $_SESSION['_expire'] = $this->_expire;

      // Refresh location data
      $this->refreshLocation();

      $this->_logged_in = true;
      $this->_logger->info('User logged in', ['user_id' => $this->_id]);

      return true;
    } catch (\Throwable $e) {
      self::_addError(
        'login',
        $e->getCode() ?: 256,
        $e->getMessage(),
        $e->getFile(),
        $e->getLine(),
        AccessRank::DEVELOPER->value
      );
      $this->_logger->error('Login failed', ['exception' => $e]);
      return false;
    }
  }

  /**
   * Logs out the current user and clears session data.
   *
   * @return bool True on success.
   */
  public function logout():bool {
    if ($this->_logged_in) {
      $this->_logger->info('User logged out', ['user_id' => $this->_id]);
    }

    // Clear session data
    $_SESSION = [];

    // Expire the session cookie
    if (\ini_get('session.use_cookies')) {
      $params = \session_get_cookie_params();
      \setcookie(\session_name(), '', [
        'expires'  => \time() - 42000,
        'path'     => $params['path'],
        'domain'   => $params['domain'],
        'secure'   => $params['secure'],
        'httponly' => $params['httponly'],
        'samesite' => 'Lax',
      ]);
    }

    \session_destroy();

    // Reset properties
    $this->_logged_in    = false;
    $this->_id           = null;
    $this->name         = 'GUEST_' . \time();
    $this->_expire       = 0;
    $this->_location     = null;
    $this->_user         = null;
    $this->_access_group = AccessGroup::GUEST;
    $this->_access_rank  = AccessRank::GUEST->value;

    return true;
  }

  // =========================================================================
  // Session Expiry
  // =========================================================================

  /**
   * Returns the session expiration timestamp.
   */
  public function getExpiry():int {
    return $this->_expire;
  }

  /**
   * Checks if session has expired.
   */
  public function isExpired():bool {
    return $this->_expire > 0 && $this->_expire < \time();
  }

  /**
   * Extends the session expiration time.
   *
   * @param int $seconds Number of seconds from now.
   * @return bool True on success.
   */
  public function extendExpiry(int $seconds):bool {
    if ($seconds <= 0) {
      return false;
    }
    $this->_expire       = \time() + $seconds;
    $_SESSION['_expire'] = $this->_expire;
    return true;
  }

  // =========================================================================
  // Location
  // =========================================================================

  /**
   * Refreshes the user's location from server-side IP geolocation.
   *
   * @return bool True on success, false on failure.
   */
  public function refreshLocation():bool {
    if (!\class_exists('TimeFrontiers\Location')) {
      self::_addError(
        'location',
        256,
        'Location class not available. Install timefrontiers/php-location.',
        __FILE__,
        __LINE__,
        AccessRank::DEVELOPER->value
      );
      return false;
    }

    try {
      $loc = new Location();
      $this->_location = (object)[
        'ip'              => $loc->ip              ?? null,
        'city'            => $loc->city            ?? null,
        'city_code'       => $loc->city_code       ?? null,
        'state'           => $loc->state           ?? null,
        'state_code'      => $loc->state_code      ?? null,
        'country'         => $loc->country         ?? null,
        'country_code'    => $loc->country_code    ?? null,
        'currency_code'   => $loc->currency_code   ?? null,
        'currency_symbol' => $loc->currency_symbol ?? null,
        'latitude'        => $loc->latitude        ?? null,
        'longitude'       => $loc->longitude       ?? null,
      ];
      $_SESSION['location'] = $this->_location;
      return true;
    } catch (\Throwable $e) {
      self::_addError(
        'location',
        $e->getCode() ?: 256,
        $e->getMessage(),
        $e->getFile(),
        $e->getLine(),
        AccessRank::DEVELOPER->value
      );
      $this->_logger->error('Location refresh failed', ['exception' => $e]);
      return false;
    }
  }

  // =========================================================================
  // CSRF Protection
  // =========================================================================

  /**
   * Generates a CSRF token for a given form identifier.
   *
   * Expired tokens for other forms are pruned on each call.
   *
   * @param string $form_id Unique identifier for the form/action.
   * @param int $expiry_seconds Token lifetime in seconds (default 3600).
   * @return string The generated token to be embedded in the form.
   */
  public function generateCSRFToken(string $form_id, int $expiry_seconds = 3600):string {
    // Prune expired tokens to prevent session bloat
    if (!empty($_SESSION['csrf_tokens'])) {
      $now = \time();
      foreach ($_SESSION['csrf_tokens'] as $id => $data) {
        if ($data['expire'] < $now) {
          unset($_SESSION['csrf_tokens'][$id]);
        }
      }
    }

    $token = \bin2hex(\random_bytes(32));
    $_SESSION['csrf_tokens'][$form_id] = [
      'token'  => $token,
      'expire' => \time() + $expiry_seconds,
    ];
    return $token;
  }

  /**
   * Validates a CSRF token for a given form identifier.
   *
   * Tokens are one-time use; they are removed after validation.
   *
   * @param string $form_id The form identifier.
   * @param string $token The token received from the request.
   * @return bool True if token is valid and not expired.
   */
  public function validateCSRFToken(string $form_id, string $token):bool {
    if (!isset($_SESSION['csrf_tokens'][$form_id])) {
      return false;
    }

    $stored = $_SESSION['csrf_tokens'][$form_id];
    unset($_SESSION['csrf_tokens'][$form_id]); // Single use

    if (\time() > $stored['expire']) {
      return false;
    }

    return \hash_equals($stored['token'], $token);
  }

  /**
   * Generates a hidden input field with CSRF token.
   *
   * @param string $form_id Form identifier.
   * @param string $field_name Input field name (default: '_csrf_token').
   * @return string HTML hidden input.
   */
  public function csrfField(string $form_id, string $field_name = '_csrf_token'):string {
    $token = $this->generateCSRFToken($form_id);
    return '<input type="hidden" name="' . \htmlspecialchars($field_name) . '" value="' . \htmlspecialchars($token) . '">';
  }

  // =========================================================================
  // User Object Storage
  // =========================================================================

  /**
   * Sets a property on the user object (and syncs to session).
   */
  public function set(string $key, mixed $value):void {
    if ($this->_user === null) {
      $this->_user = new \stdClass();
    }
    $this->_user->$key = $value;
    $_SESSION['user']  = $this->_user;
  }

  /**
   * Retrieves a property from the user object.
   */
  public function get(string $key, mixed $default = null):mixed {
    return $this->_user->$key ?? $default;
  }

  /**
   * Checks if a property exists on the user object.
   */
  public function has(string $key):bool {
    return isset($this->_user->$key);
  }

  /**
   * Removes a property from the user object (and syncs to session).
   */
  public function remove(string $key):void {
    if ($this->_user !== null) {
      unset($this->_user->$key);
      $_SESSION['user'] = $this->_user;
    }
  }

  /**
   * Returns all properties on the user object as an array.
   */
  public function all():array {
    return $this->_user !== null ? (array)$this->_user : [];
  }

  // =========================================================================
  // Flash Messages
  // =========================================================================

  /**
   * Sets a flash message (available for one request).
   */
  public function flash(string $key, mixed $value):void {
    $_SESSION['_flash'][$key] = $value;
  }

  /**
   * Gets and removes a flash message.
   */
  public function getFlash(string $key, mixed $default = null):mixed {
    $value = $_SESSION['_flash'][$key] ?? $default;
    unset($_SESSION['_flash'][$key]);
    return $value;
  }

  /**
   * Checks if a flash message exists.
   */
  public function hasFlash(string $key):bool {
    return isset($_SESSION['_flash'][$key]);
  }

  // =========================================================================
  // Access Control Helpers
  // =========================================================================

  /**
   * Checks if user has at least the given rank.
   */
  public function hasRank(AccessRank|int $rank):bool {
    $required = $rank instanceof AccessRank ? $rank->value : $rank;
    return $this->_access_rank >= $required;
  }

  /**
   * Checks if user is in the given group.
   */
  public function inGroup(AccessGroup|string $group):bool {
    $check = $group instanceof AccessGroup ? $group : AccessGroup::tryFrom($group);
    return $check !== null && $this->_access_group === $check;
  }

  /**
   * Checks if user is at least a staff member.
   */
  public function isStaff():bool {
    return $this->_access_rank >= AccessRank::MODERATOR->value;
  }

  /**
   * Checks if user is technical (developer or higher).
   */
  public function isTechnical():bool {
    return $this->_access_rank >= AccessRank::DEVELOPER->value;
  }

  /**
   * Checks if user is an admin.
   */
  public function isAdmin():bool {
    return $this->_access_rank >= AccessRank::ADMIN->value;
  }

  // =========================================================================
  // Backward Compatibility (deprecated)
  // =========================================================================

  /**
   * @deprecated Use generateCSRFToken() instead.
   */
  public function createCSRFtoken(string $form, int $expiry = 0):string {
    $seconds = 2700; // 45 min default from original
    if ($expiry > \time()) {
      $seconds = $expiry - \time();
    } elseif ($expiry > 0) {
      $seconds = $expiry;
    }
    return $this->generateCSRFToken($form, $seconds);
  }

  /**
   * @deprecated Use validateCSRFToken() instead.
   */
  public function isValidCSRFtoken(string $form, string $token, int $token_exp = 0):bool {
    return $this->validateCSRFToken($form, $token);
  }

  // =========================================================================
  // Static Error Handling
  // =========================================================================

  /**
   * Adds an error to the static collection.
   *
   * @param string $context Error context (e.g., method name).
   * @param int $code Error code.
   * @param string $message Error message.
   * @param string $file File where error occurred.
   * @param int $line Line number.
   * @param int $min_rank Minimum AccessRank value required to view this error.
   */
  protected static function _addError(
    string $context,
    int $code,
    string $message,
    string $file,
    int $line,
    int $min_rank = 0
  ):void {
    self::$_errors[$context][] = [
      $min_rank,
      $code,
      $message,
      $file,
      $line,
    ];
  }

  /**
   * Returns all static errors.
   */
  public function getErrors():array {
    return self::$_errors;
  }

  /**
   * Checks if any errors exist.
   */
  public function hasErrors():bool {
    return !empty(self::$_errors);
  }

  /**
   * Clears all static errors.
   */
  public static function clearErrors():void {
    self::$_errors = [];
  }

  // =========================================================================
  // Private Helpers
  // =========================================================================

  /**
   * Configures secure session cookie parameters.
   */
  private function _configureSessionCookie():void {
    $params = \session_get_cookie_params();
    \session_set_cookie_params([
      'lifetime' => $params['lifetime'],
      'path'     => '/',
      'domain'   => $params['domain'],
      'secure'   => isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
      'httponly' => true,
      'samesite' => 'Lax',
    ]);
  }

  /**
   * Checks if a valid session exists and restores state.
   */
  private function _checkLogin():void {
    if (
      isset($_SESSION['user'], $_SESSION['_expire']) &&
      \is_object($_SESSION['user']) &&
      (int)$_SESSION['_expire'] > \time()
    ) {
      $this->_user  = $_SESSION['user'];
      $this->_id    = $this->_user->id ?? null;
      $this->name  = $_SESSION['name'] ?? '';

      $this->_access_group = isset($_SESSION['access_group'])
        ? $this->_normalizeAccessGroup($_SESSION['access_group'])
        : AccessGroup::USER;
      $this->_access_rank = isset($_SESSION['access_rank'])
        ? \max(0, (int)$_SESSION['access_rank'])
        : AccessRank::USER->value;

      $this->_expire   = (int)$_SESSION['_expire'];
      $this->_location = (!empty($_SESSION['location']) && \is_object($_SESSION['location']))
        ? $_SESSION['location']
        : null;

      $this->_logged_in = true;
    } else {
      $this->_clearSession();
    }
  }

  /**
   * Clears authentication-related session data.
   */
  private function _clearSession():void {
    unset(
      $_SESSION['user'],
      $_SESSION['name'],
      $_SESSION['_expire'],
      $_SESSION['access_group'],
      $_SESSION['access_rank'],
      $_SESSION['location']
    );
    $this->_logged_in = false;
    $this->_user      = null;
    $this->_id        = null;
    $this->_expire    = 0;
  }

  /**
   * Recursively converts an object into a plain stdClass safe for PHP session
   * serialization. Backed enums become their scalar value, unit enums become
   * their name, and anything non-serializable (resources, closures) is dropped.
   */
  private function _sanitizeUser(object $user):\stdClass {
    $safe = new \stdClass();
    foreach (\get_object_vars($user) as $key => $value) {
      $safe->$key = match(true) {
        $value instanceof \BackedEnum => $value->value,
        $value instanceof \UnitEnum  => $value->name,
        $value instanceof \stdClass  => $this->_sanitizeUser($value),
        \is_object($value)           => $this->_sanitizeUser($value),
        \is_resource($value)         => null,
        default                      => $value,
      };
    }
    return $safe;
  }

  /**
   * Normalizes input to an AccessGroup enum.
   */
  private function _normalizeAccessGroup(mixed $group):AccessGroup {
    if ($group instanceof AccessGroup) {
      return $group;
    }
    if (\is_string($group)) {
      return AccessGroup::tryFrom($group) ?? AccessGroup::USER;
    }
    return AccessGroup::USER;
  }

  /**
   * Normalizes input to an integer access rank.
   * Handles AccessRank enum, int, and numeric strings (e.g. from database).
   */
  private function _normalizeAccessRank(mixed $rank):int {
    if ($rank instanceof AccessRank) {
      return $rank->value;
    }
    if (\is_int($rank) || (\is_string($rank) && \is_numeric($rank))) {
      $enum = AccessRank::tryFrom((int)$rank);
      return $enum ? $enum->value : AccessRank::USER->value;
    }
    return AccessRank::USER->value;
  }
}
