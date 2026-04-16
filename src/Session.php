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
 *   // Login user
 *   $session->login($user, remember: true);
 * }
 *
 * // Access control
 * if ($session->access_rank >= AccessRank::MODERATOR->value) {
 *   // Show admin panel
 * }
 *
 * // CSRF protection
 * $token = $session->generateCSRFToken('contact_form');
 * // In form handler:
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
   * @var string Public unique identifier (e.g., username, public ID).
   */
  public string $name = '';

  /**
   * @var AccessGroup The user's access group.
   */
  public readonly AccessGroup $access_group;

  /**
   * @var int The user's access rank (value from AccessRank enum).
   */
  public readonly int $access_rank;

  /**
   * @var object|null The user's geolocation information.
   */
  public ?object $location = null;

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
      $this->access_group = AccessGroup::GUEST;
      $this->access_rank = AccessRank::GUEST->value;
      $this->name = 'GUEST_' . \time();
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
  // Login / Logout
  // =========================================================================

  /**
   * Logs in a user.
   *
   * @param object $user User object with at least 'id' and a public identifier
   *                     ('name' or 'uniqueid'). May also contain 'access_group'
   *                     and 'access_rank'.
   * @param bool $remember If true, sets a long-lived "remember me" cookie.
   * @param int $session_lifetime Session lifetime in seconds (default 30 minutes).
   * @return bool True on success, false on failure (errors in self::$_errors).
   */
  public function login(
    object $user,
    bool $remember = false,
    int $session_lifetime = 1800
  ):bool {
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

    // Determine public name
    $public_name = $user->name ?? $user->uniqueid ?? null;
    if ($public_name === null) {
      self::_addError(
        'login',
        256,
        'User object must have a public identifier ("name" or "uniqueid").',
        __FILE__,
        __LINE__,
        AccessRank::DEVELOPER->value
      );
      return false;
    }

    try {
      // Regenerate session ID to prevent fixation
      \session_regenerate_id(true);

      $this->_id = $user->id;
      $this->name = (string)$public_name;
      $_SESSION['user_id'] = $this->_id;
      $_SESSION['user_name'] = $this->name;

      // Set access group and rank
      $group = $this->_normalizeAccessGroup($user->access_group ?? null);
      $rank = $this->_normalizeAccessRank($user->access_rank ?? null);

      // Use reflection to set readonly properties
      $this->_setReadonly('access_group', $group);
      $this->_setReadonly('access_rank', $rank);

      $_SESSION['access_group'] = $group->value;
      $_SESSION['access_rank'] = $rank;

      // Set expiration
      $this->_expire = \time() + $session_lifetime;
      $_SESSION['_expire'] = $this->_expire;

      // Refresh location data
      $this->refreshLocation();

      // Handle "remember me" functionality
      if ($remember) {
        $this->_setRememberMeCookie($this->_id);
      }

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
    $this->_clearRememberMeCookie();

    // Destroy session cookie
    if (\ini_get('session.use_cookies')) {
      $params = \session_get_cookie_params();
      \setcookie(
        \session_name(),
        '',
        \time() - 42000,
        $params['path'],
        $params['domain'],
        $params['secure'],
        $params['httponly']
      );
    }

    \session_destroy();
    \session_regenerate_id(true);

    // Reset properties
    $this->_logged_in = false;
    $this->_id = null;
    $this->name = 'GUEST_' . \time();
    $this->_expire = 0;
    $this->location = null;
    $this->_setReadonly('access_group', AccessGroup::GUEST);
    $this->_setReadonly('access_rank', AccessRank::GUEST->value);

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
    $this->_expire = \time() + $seconds;
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
      $this->location = (object)[
        'ip'              => $loc->ip,
        'city'            => $loc->city,
        'city_code'       => $loc->city_code,
        'state'           => $loc->state,
        'state_code'      => $loc->state_code,
        'country'         => $loc->country,
        'country_code'    => $loc->country_code,
        'currency_code'   => $loc->currency_code,
        'currency_symbol' => $loc->currency_symbol,
        'latitude'        => $loc->latitude,
        'longitude'       => $loc->longitude,
      ];
      $_SESSION['location'] = $this->location;
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
   * @param string $form_id Unique identifier for the form/action.
   * @param int $expiry_seconds Token lifetime in seconds (default 3600).
   * @return string The generated token to be embedded in the form.
   */
  public function generateCSRFToken(string $form_id, int $expiry_seconds = 3600):string {
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
  // Session Storage
  // =========================================================================

  /**
   * Stores arbitrary data in the session.
   */
  public function set(string $key, mixed $value):void {
    $_SESSION[$key] = $value;
  }

  /**
   * Retrieves arbitrary data from the session.
   */
  public function get(string $key, mixed $default = null):mixed {
    return $_SESSION[$key] ?? $default;
  }

  /**
   * Checks if a key exists in the session.
   */
  public function has(string $key):bool {
    return isset($_SESSION[$key]);
  }

  /**
   * Removes a key from the session.
   */
  public function remove(string $key):void {
    unset($_SESSION[$key]);
  }

  /**
   * Gets all session data.
   */
  public function all():array {
    return $_SESSION;
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
    return $this->access_rank >= $required;
  }

  /**
   * Checks if user is in the given group.
   */
  public function inGroup(AccessGroup|string $group):bool {
    $check = $group instanceof AccessGroup ? $group : AccessGroup::tryFrom($group);
    return $check !== null && $this->access_group === $check;
  }

  /**
   * Checks if user is at least a staff member.
   */
  public function isStaff():bool {
    return $this->access_rank >= AccessRank::MODERATOR->value;
  }

  /**
   * Checks if user is technical (developer or higher).
   */
  public function isTechnical():bool {
    return $this->access_rank >= AccessRank::DEVELOPER->value;
  }

  /**
   * Checks if user is an admin.
   */
  public function isAdmin():bool {
    return $this->access_rank >= AccessRank::ADMIN->value;
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
      isset($_SESSION['user_id'], $_SESSION['_expire']) &&
      $_SESSION['_expire'] > \time()
    ) {
      $this->_logged_in = true;
      $this->_id = $_SESSION['user_id'];
      $this->name = $_SESSION['user_name'] ?? '';

      $group = isset($_SESSION['access_group'])
        ? $this->_normalizeAccessGroup($_SESSION['access_group'])
        : AccessGroup::USER;
      $rank = isset($_SESSION['access_rank'])
        ? \max(0, (int)$_SESSION['access_rank'])
        : AccessRank::USER->value;

      $this->_setReadonly('access_group', $group);
      $this->_setReadonly('access_rank', $rank);

      $this->_expire = (int)$_SESSION['_expire'];
      $this->location = $_SESSION['location'] ?? null;
    } else {
      $this->_clearSession();
    }
  }

  /**
   * Clears authentication-related session data.
   */
  private function _clearSession():void {
    unset(
      $_SESSION['user_id'],
      $_SESSION['user_name'],
      $_SESSION['_expire'],
      $_SESSION['access_group'],
      $_SESSION['access_rank'],
      $_SESSION['location']
    );
    $this->_logged_in = false;
    $this->_id = null;
    $this->_expire = 0;
  }

  /**
   * Sets a readonly property using reflection.
   */
  private function _setReadonly(string $property, mixed $value):void {
    $ref = new \ReflectionProperty($this, $property);
    $ref->setValue($this, $value);
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
   */
  private function _normalizeAccessRank(mixed $rank):int {
    if ($rank instanceof AccessRank) {
      return $rank->value;
    }
    if (\is_int($rank)) {
      $enum = AccessRank::tryFrom($rank);
      return $enum ? $enum->value : AccessRank::USER->value;
    }
    return AccessRank::USER->value;
  }

  /**
   * Sets a secure "remember me" cookie.
   */
  private function _setRememberMeCookie(int|string $user_id):void {
    $token = \bin2hex(\random_bytes(32));
    // TODO: Store hash of $token with $user_id and expiry in database.

    $value = $user_id . ':' . $token;
    \setcookie('remember_me', $value, [
      'expires'  => \time() + 86400 * 30, // 30 days
      'path'     => '/',
      'secure'   => true,
      'httponly' => true,
      'samesite' => 'Lax',
    ]);
  }

  /**
   * Clears the "remember me" cookie.
   */
  private function _clearRememberMeCookie():void {
    \setcookie('remember_me', '', \time() - 3600, '/', '', true, true);
  }
}
