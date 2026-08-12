<?php

declare(strict_types=1);

namespace TimeFrontiers;

use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use TimeFrontiers\Helper\HasErrors;

/**
 * Secure PHP session lifecycle, authentication state, CSRF, flash, and access.
 *
 * Password verification and trusted-proxy parsing deliberately remain outside
 * this package. Callers must supply a trusted, bounded identity projection.
 */
final class Session {

  use HasErrors {
    _addError as private traitAddError;
    getErrors as private traitGetErrors;
    hasErrors as private traitHasErrors;
    clearErrors as private traitClearErrors;
    errorCount as private;
    firstError as private;
    errorMessages as private;
  }

  private const STORAGE_KEY = '_timefrontiers_session';
  private const STORAGE_VERSION = 1;
  private const AUTH_VERSION = 1;
  private const LEGACY_AUTH_KEYS = [
    'user',
    'name',
    '_expire',
    'access_group',
    'access_rank',
    'location',
  ];
  private const RESERVED_ATTRIBUTE_KEYS = [
    'id',
    'uniqueid',
    'access_group',
    'access_rank',
  ];
  private const LOCATION_FIELDS = [
    'ip',
    'city',
    'city_code',
    'state',
    'state_code',
    'country',
    'country_code',
    'currency_code',
    'currency_symbol',
    'latitude',
    'longitude',
  ];

  private const LOGIN_INVALID = 1101;
  private const LOGIN_ROTATION_FAILED = 1102;
  private const RESTORE_INVALID = 1201;
  private const LOGOUT_INCOMPLETE = 1301;
  private const EXPIRY_UPDATE_FAILED = 1401;
  private const LOCATION_FAILED = 1501;
  private const STORAGE_INVALID = 1601;

  private bool $_logged_in = false;
  private int $_expire = 0;
  private int $_idle_expires_at = 0;
  private int $_absolute_expires_at = 0;
  private int|string|null $_id = null;
  private LoggerInterface $_logger;
  private SessionConfig $_config;
  private SessionRuntimeInterface $_runtime;
  private SessionValuePolicy $_values;

  /** @var array<string, string|int|float|bool|null> */
  private array $_identity = [];

  /** @var array<string, mixed> */
  private array $_attributes = [];

  /** @var \WeakMap<self, true>|null */
  private static ?\WeakMap $_instances = null;

  /** The authenticated uniqueid, or a non-security guest display value. */
  public string $name = '';

  protected ?object $_location = null;
  protected ?object $_user = null;
  protected AccessGroup $_access_group = AccessGroup::GUEST;
  protected int $_access_rank = AccessRank::GUEST->value;

  /**
   * @throws SessionException When the session cannot be safely configured.
   */
  public function __construct(
    ?LoggerInterface $logger = null,
    ?SessionConfig $config = null
  ) {
    $this->_logger = $logger ?? new NullLogger();
    $this->_config = $config ?? new SessionConfig();
    $this->_runtime = $this->_config->runtime;
    $this->_values = new SessionValuePolicy($this->_config);

    $this->bootstrap();
    self::$_instances ??= new \WeakMap();
    self::$_instances[$this] = true;

    if (!isset($_SESSION)) {
      $_SESSION = [];
    }
    $this->resetGuest();
    $this->restore();
  }

  public function isLoggedIn():bool {
    return $this->_logged_in;
  }

  public function loggedIn():bool {
    return $this->isLoggedIn();
  }

  public function getUserId():int|string|null {
    return $this->_id;
  }

  public function id():int|string|null {
    return $this->getUserId();
  }

  public function user():?object {
    return $this->_user;
  }

  public function location():?object {
    return $this->_location;
  }

  public function access_group():AccessGroup {
    return $this->_access_group;
  }

  public function access_rank():int {
    return $this->_access_rank;
  }

  /**
   * Commit a trusted authentication projection after rotating the session ID.
   */
  public function login(object $user, int $session_lifetime = 1800):bool {
    $this->clearErrorContext('login');

    try {
      $payload = $this->buildAuthenticationPayload($user, $session_lifetime);
      $root = $this->root();
      // CSRF tokens belong to the privilege context in which they were
      // minted. Drop guest/pre-authentication tokens from the candidate root;
      // the live guest state remains untouched if ID rotation later fails.
      unset($root['csrf'], $root['location']);
      $root['auth'] = $payload;
      $this->_values->assertSessionSize($root);
    } catch (\Throwable $cause) {
      $this->addSafeError(
        'login',
        self::LOGIN_INVALID,
        'The supplied session identity is invalid.',
        AccessRank::GUEST->value
      );
      $this->_logger->warning('session.login.rejected', ['exception' => $cause]);
      return false;
    }

    if (
      $this->_runtime->status() !== PHP_SESSION_ACTIVE
      || $this->_runtime->headersSent()
    ) {
      $cause = $this->_runtime->headersSent()
        ? SessionException::headersAlreadySent()
        : SessionException::regenerateFailed();
      $this->recordLoginRotationFailure($cause);
      return false;
    }

    if (!$this->_runtime->regenerateId(true)) {
      $this->recordLoginRotationFailure(SessionException::regenerateFailed());
      return false;
    }

    $_SESSION[self::STORAGE_KEY] = $root;
    $this->adoptAuthentication($payload);
    $this->_location = null;
    $this->_logger->info('session.login.succeeded');
    return true;
  }

  /**
   * Destroy the server session and matching client cookie.
   *
   * Local identity is always cleared, even if external cleanup fails.
   */
  public function logout():bool {
    $this->clearErrorContext('logout');
    if ($this->_logged_in) {
      $this->_logger->info('session.logout.requested');
    }

    $wasActive = $this->_runtime->status() === PHP_SESSION_ACTIVE;
    $this->resetGuest(clearAttributes: true);
    $_SESSION = [];

    if (!$wasActive) {
      return true;
    }

    $complete = true;
    if ($this->_runtime->headersSent()) {
      $complete = false;
      $this->addSafeError(
        'logout',
        self::LOGOUT_INCOMPLETE,
        'The session could not be completely closed.',
        AccessRank::GUEST->value
      );
    } else {
      if (!$this->_runtime->regenerateId(true)) {
        $complete = false;
        $this->addSafeError(
          'logout',
          self::LOGOUT_INCOMPLETE,
          'The session could not be completely closed.',
          AccessRank::GUEST->value
        );
      }

      if (!$this->_runtime->setCookie(
        $this->_config->cookieName,
        '',
        $this->_config->cookieOptions($this->_runtime->now() - 42000)
      )) {
        $complete = false;
        $this->addSafeError(
          'logout',
          self::LOGOUT_INCOMPLETE,
          'The session could not be completely closed.',
          AccessRank::GUEST->value
        );
      }
    }

    if (!$this->_runtime->destroy()) {
      $complete = false;
      $this->addSafeError(
        'logout',
        self::LOGOUT_INCOMPLETE,
        'The session could not be completely closed.',
        AccessRank::GUEST->value
      );
      $this->_logger->error('session.logout.failed', [
        'exception' => SessionException::destructionFailed(),
      ]);
    }

    return $complete;
  }

  public function getExpiry():int {
    return $this->_expire;
  }

  public function isExpired():bool {
    return $this->_logged_in
      && $this->_expire > 0
      && $this->_expire <= $this->_runtime->now();
  }

  /**
   * Explicitly extend the idle window without changing the absolute lifetime.
   */
  public function extendExpiry(int $seconds):bool {
    $this->clearErrorContext('expiry');
    if (!$this->_logged_in || $seconds <= 0 || $this->isExpired()) {
      if ($this->isExpired()) {
        $this->invalidateAuthentication(false);
      }
      return false;
    }

    $now = $this->_runtime->now();
    $duration = \min(
      $seconds,
      $this->_config->maxExpiryExtension,
      $this->_config->maxIdleLifetime
    );
    $idleExpiry = \min($now + $duration, $this->_absolute_expires_at);
    $effectiveExpiry = \min($idleExpiry, $this->_absolute_expires_at);
    if ($effectiveExpiry <= $this->_expire) {
      return false;
    }

    $root = $this->root();
    $auth = $root['auth'] ?? null;
    if (!\is_array($auth)) {
      $this->invalidateAuthentication(true);
      return false;
    }
    $auth['idle_expires_at'] = $idleExpiry;
    $root['auth'] = $auth;

    try {
      $this->_values->assertSessionSize($root);
    } catch (\Throwable $cause) {
      $this->_logger->error('session.expiry.failed', ['exception' => $cause]);
      $this->addSafeError(
        'expiry',
        self::EXPIRY_UPDATE_FAILED,
        'The session expiry could not be extended.',
        AccessRank::GUEST->value
      );
      return false;
    }

    if ($this->_config->cookieLifetime > 0) {
      if ($this->_runtime->headersSent()) {
        $this->addSafeError(
          'expiry',
          self::EXPIRY_UPDATE_FAILED,
          'The session expiry could not be extended.',
          AccessRank::GUEST->value
        );
        return false;
      }
      $cookieExpiry = \min($now + $this->_config->cookieLifetime, $effectiveExpiry);
      if (!$this->_runtime->setCookie(
        $this->_config->cookieName,
        $this->_runtime->id(),
        $this->_config->cookieOptions($cookieExpiry)
      )) {
        $this->addSafeError(
          'expiry',
          self::EXPIRY_UPDATE_FAILED,
          'The session expiry could not be extended.',
          AccessRank::GUEST->value
        );
        return false;
      }
    }

    $_SESSION[self::STORAGE_KEY] = $root;
    $this->_idle_expires_at = $idleExpiry;
    $this->_expire = $effectiveExpiry;
    return true;
  }

  /**
   * Explicit optional enrichment. This method never controls authentication.
   */
  public function refreshLocation():bool {
    $this->clearErrorContext('location');
    if (!$this->_config->locationEnabled) {
      return false;
    }

    try {
      if ($this->_config->locationResolver !== null) {
        $source = ($this->_config->locationResolver)();
      } elseif (\class_exists(Location::class)) {
        $source = new Location();
      } else {
        if ($this->_config->locationRequired) {
          $this->addSafeError(
            'location',
            self::LOCATION_FAILED,
            'Location enrichment is unavailable.',
            AccessRank::GUEST->value
          );
        }
        return false;
      }

      if (!\is_object($source) && !\is_array($source)) {
        throw new \UnexpectedValueException('Invalid location result.');
      }

      $sourceValues = (array)$source;
      $location = [];
      foreach (self::LOCATION_FIELDS as $field) {
        $location[$field] = $this->_values->normalizeValue($sourceValues[$field] ?? null);
      }

      $root = $this->root();
      $root['location'] = $location;
      $this->_values->assertSessionSize($root);
      $_SESSION[self::STORAGE_KEY] = $root;
      $this->_location = (object)$location;
      return true;
    } catch (\Throwable $cause) {
      $this->_logger->error('session.location.failed', ['exception' => $cause]);
      if ($this->_config->locationRequired) {
        $this->addSafeError(
          'location',
          self::LOCATION_FAILED,
          'Location enrichment is unavailable.',
          AccessRank::GUEST->value
        );
      }
      return false;
    }
  }

  public function generateCSRFToken(string $form_id, int $expiry_seconds = 3600):string {
    $this->assertCsrfInput($form_id, $expiry_seconds);
    $now = $this->_runtime->now();
    $root = $this->root();
    $store = $this->pruneCsrfStore($root['csrf'] ?? [], $now);

    $token = \bin2hex($this->_runtime->randomBytes(32));
    $store[$form_id] ??= [];
    $store[$form_id][] = [
      'hash' => \hash('sha256', $token),
      'expires_at' => $now + $expiry_seconds,
      'created_at' => $now,
    ];

    if (\count($store[$form_id]) > $this->_config->csrfTokensPerForm) {
      $store[$form_id] = \array_slice(
        $store[$form_id],
        -$this->_config->csrfTokensPerForm
      );
    }
    $store = $this->enforceGlobalCsrfCap($store);
    $root['csrf'] = $store;
    $this->_values->assertSessionSize($root);
    $_SESSION[self::STORAGE_KEY] = $root;
    return $token;
  }

  public function validateCSRFToken(string $form_id, string $token):bool {
    if (
      !$this->isValidFormId($form_id)
      || $token === ''
      || \strlen($token) > 4096
    ) {
      return false;
    }

    $root = $this->root();
    $store = $this->pruneCsrfStore(
      $root['csrf'] ?? [],
      $this->_runtime->now()
    );
    $candidateHash = \hash('sha256', $token);
    $matched = null;

    foreach ($store[$form_id] ?? [] as $index => $entry) {
      $isMatch = \hash_equals($entry['hash'], $candidateHash);
      if ($isMatch && $matched === null) {
        $matched = $index;
      }
    }

    if ($matched !== null) {
      unset($store[$form_id][$matched]);
      $store[$form_id] = \array_values($store[$form_id]);
      if ($store[$form_id] === []) {
        unset($store[$form_id]);
      }
    }

    $root['csrf'] = $store;
    $_SESSION[self::STORAGE_KEY] = $root;
    return $matched !== null;
  }

  public function csrfField(string $form_id, string $field_name = '_csrf_token'):string {
    $token = $this->generateCSRFToken($form_id);
    return '<input type="hidden" name="'
      . \htmlspecialchars($field_name, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')
      . '" value="'
      . \htmlspecialchars($token, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')
      . '">';
  }

  public function set(string $key, mixed $value):void {
    $this->assertMutableAttributeKey($key);
    $safe = $this->_values->normalizeValue($value);
    $attributes = $this->_attributes;
    $attributes[$key] = $safe;

    $root = $this->root();
    $root['attributes'] = $attributes;
    $this->_values->assertSessionSize($root);
    $_SESSION[self::STORAGE_KEY] = $root;
    $this->_attributes = $attributes;
    $this->syncUserView();
  }

  public function get(string $key, mixed $default = null):mixed {
    if (\array_key_exists($key, $this->_attributes)) {
      return $this->_attributes[$key];
    }
    if (\array_key_exists($key, $this->_identity)) {
      return $this->_identity[$key];
    }
    return $default;
  }

  public function has(string $key):bool {
    return \array_key_exists($key, $this->_attributes)
      || \array_key_exists($key, $this->_identity);
  }

  public function remove(string $key):void {
    $this->assertMutableAttributeKey($key);
    if (!\array_key_exists($key, $this->_attributes)) {
      return;
    }

    unset($this->_attributes[$key]);
    $root = $this->root();
    $root['attributes'] = $this->_attributes;
    $_SESSION[self::STORAGE_KEY] = $root;
    $this->syncUserView();
  }

  /** @return array<string, mixed> */
  public function all():array {
    return \array_replace($this->_identity, $this->_attributes);
  }

  public function flash(string $key, mixed $value):void {
    $this->_values->assertKey($key);
    $safe = $this->_values->normalizeValue($value);
    $root = $this->root();
    $flash = isset($root['flash']) && \is_array($root['flash']) ? $root['flash'] : [];
    $flash[$key] = $safe;
    $root['flash'] = $flash;
    $this->_values->assertSessionSize($root);
    $_SESSION[self::STORAGE_KEY] = $root;
  }

  public function getFlash(string $key, mixed $default = null):mixed {
    $root = $this->root();
    $flash = isset($root['flash']) && \is_array($root['flash']) ? $root['flash'] : [];
    if (!\array_key_exists($key, $flash)) {
      return $default;
    }

    $value = $flash[$key];
    unset($flash[$key]);
    $root['flash'] = $flash;
    $_SESSION[self::STORAGE_KEY] = $root;
    return $value;
  }

  public function hasFlash(string $key):bool {
    $root = $this->root();
    return isset($root['flash'])
      && \is_array($root['flash'])
      && \array_key_exists($key, $root['flash']);
  }

  public function hasRank(AccessRank|int $rank):bool {
    $required = $rank instanceof AccessRank ? $rank->value : $rank;
    return $this->_access_rank >= $required;
  }

  public function inGroup(AccessGroup|string $group):bool {
    $candidate = $group instanceof AccessGroup ? $group : AccessGroup::tryFrom($group);
    return $candidate !== null && $this->_access_group === $candidate;
  }

  public function isStaff():bool {
    return $this->_access_group->isStaff();
  }

  public function isTechnical():bool {
    return $this->_access_group->isTechnical();
  }

  public function isAdmin():bool {
    return $this->_access_group->isAdmin();
  }

  /** @deprecated Use generateCSRFToken(). */
  public function createCSRFtoken(string $form, int $expiry = 0):string {
    \trigger_error(
      'Session::createCSRFtoken() is deprecated; use generateCSRFToken().',
      E_USER_DEPRECATED
    );
    $seconds = 2700;
    if ($expiry > $this->_runtime->now()) {
      $seconds = $expiry - $this->_runtime->now();
    } elseif ($expiry > 0) {
      $seconds = $expiry;
    }
    return $this->generateCSRFToken($form, $seconds);
  }

  /** @deprecated Use validateCSRFToken(). */
  public function isValidCSRFtoken(string $form, string $token, int $token_exp = 0):bool {
    \trigger_error(
      'Session::isValidCSRFtoken() is deprecated; use validateCSRFToken().',
      E_USER_DEPRECATED
    );
    return $this->validateCSRFToken($form, $token);
  }

  /** @return array<string, array<int, array{int,int,string,string,int}>> */
  public function getErrors():array {
    /** @var array<string, array<int, array{int,int,string,string,int}>> $errors */
    $errors = $this->traitGetErrors();
    return $errors;
  }

  public function hasErrors():bool {
    return $this->traitHasErrors();
  }

  /**
   * Clear errors owned by this Session instance only.
   *
   * An empty context clears the instance's complete collection. Supplying a
   * context clears only that operation's tuples.
   */
  public function clearInstanceErrors(string $context = ''):void {
    $this->traitClearErrors($context);
  }

  /**
   * Compatibility wrapper. Error collections are instance-owned; this clears
   * all currently live Session instances without retaining them indefinitely.
   */
  public static function clearErrors():void {
    if (self::$_instances === null) {
      return;
    }
    foreach (self::$_instances as $instance => $_registered) {
      $instance->traitClearErrors();
    }
  }

  private function bootstrap():void {
    $status = $this->_runtime->status();
    if ($status === PHP_SESSION_DISABLED) {
      throw SessionException::startFailed();
    }

    if ($status === PHP_SESSION_ACTIVE) {
      $this->validateActiveSession();
      return;
    }

    if ($this->_runtime->headersSent()) {
      throw SessionException::headersAlreadySent();
    }

    $ini = [
      'session.use_cookies' => '1',
      'session.use_only_cookies' => $this->_config->onlyCookies ? '1' : '0',
      'session.use_strict_mode' => $this->_config->strictMode ? '1' : '0',
      'session.use_trans_sid' => '0',
      'session.gc_maxlifetime' => (string)$this->_config->absoluteLifetime,
    ];
    foreach ($ini as $key => $value) {
      if (!$this->_runtime->setIni($key, $value)) {
        throw SessionException::invalidConfiguration();
      }
    }

    if (
      $this->_runtime->name($this->_config->cookieName) === false
      || !$this->_runtime->setCookieParams($this->_config->cookieParameters())
      || !$this->_runtime->start()
    ) {
      throw SessionException::startFailed();
    }
  }

  private function validateActiveSession():void {
    $expected = $this->_config->cookieParameters();
    $actual = $this->_runtime->cookieParams();
    $actual['samesite'] = \ucfirst(\strtolower($actual['samesite']));

    if (
      $this->_runtime->name() !== $this->_config->cookieName
      || $actual['lifetime'] !== $expected['lifetime']
      || $actual['path'] !== $expected['path']
      || (string)$actual['domain'] !== $expected['domain']
      || $actual['secure'] !== $expected['secure']
      || $actual['httponly'] !== $expected['httponly']
      || $actual['samesite'] !== $expected['samesite']
      || $actual['partitioned'] !== $expected['partitioned']
      || $this->iniBoolean('session.use_cookies') !== true
      || $this->iniBoolean('session.use_only_cookies') !== $this->_config->onlyCookies
      || $this->iniBoolean('session.use_strict_mode') !== $this->_config->strictMode
      || $this->iniBoolean('session.use_trans_sid') !== false
      || $this->iniInteger('session.gc_maxlifetime') < $this->_config->absoluteLifetime
    ) {
      throw SessionException::configurationAfterStart();
    }
  }

  private function restore():void {
    $rootValue = $_SESSION[self::STORAGE_KEY] ?? [];
    if (!\is_array($rootValue)) {
      $_SESSION[self::STORAGE_KEY] = ['v' => self::STORAGE_VERSION];
      $this->invalidateAuthentication(true);
      return;
    }

    // The v1.0 sweep is a migration, not a standing rule. Once the canonical
    // root records the storage version, root keys outside this package belong
    // to the application: they are never read as authentication state and
    // never clear an active login.
    $hasLegacyAuth = false;
    if (($rootValue['v'] ?? null) !== self::STORAGE_VERSION) {
      foreach (self::LEGACY_AUTH_KEYS as $key) {
        if (\array_key_exists($key, $_SESSION)) {
          unset($_SESSION[$key]);
          $hasLegacyAuth = true;
        }
      }
    }

    try {
      $this->_attributes = $this->validateAttributeBag($rootValue['attributes'] ?? []);
      $flash = $this->validateFlashBag($rootValue['flash'] ?? []);
      $csrf = $this->pruneCsrfStore($rootValue['csrf'] ?? [], $this->_runtime->now());
    } catch (\Throwable $cause) {
      $this->_logger->warning('session.storage.rejected', ['exception' => $cause]);
      $this->addSafeError(
        'storage',
        self::STORAGE_INVALID,
        'Stored session data was discarded.',
        AccessRank::GUEST->value
      );
      $rootValue = [];
      $this->_attributes = [];
      $flash = [];
      $csrf = [];
      $_SESSION[self::STORAGE_KEY] = [];
    }

    $canonicalRoot = ['v' => self::STORAGE_VERSION];
    if ($this->_attributes !== []) {
      $canonicalRoot['attributes'] = $this->_attributes;
    }
    if ($flash !== []) {
      $canonicalRoot['flash'] = $flash;
    }
    if ($csrf !== []) {
      $canonicalRoot['csrf'] = $csrf;
    }

    if ($hasLegacyAuth) {
      $_SESSION[self::STORAGE_KEY] = $canonicalRoot;
      $this->invalidateAuthentication(false);
      return;
    }

    $auth = $rootValue['auth'] ?? null;
    $_SESSION[self::STORAGE_KEY] = $canonicalRoot;
    if ($auth === null) {
      $location = $this->restoreLocation($rootValue['location'] ?? null);
      if ($location !== null) {
        $canonicalRoot['location'] = $location;
      }
      // Oversized guest storage is discarded, never thrown out of the
      // constructor: a session the caller cannot rebuild would fail every
      // subsequent request instead of healing itself.
      try {
        $this->_values->assertSessionSize($canonicalRoot);
      } catch (\Throwable $cause) {
        $this->_logger->warning('session.storage.rejected', ['exception' => $cause]);
        $this->addSafeError(
          'storage',
          self::STORAGE_INVALID,
          'Stored session data was discarded.',
          AccessRank::GUEST->value
        );
        $this->_attributes = [];
        $this->_location = null;
        $canonicalRoot = ['v' => self::STORAGE_VERSION];
      }
      $_SESSION[self::STORAGE_KEY] = $canonicalRoot;
      return;
    }
    if (
      \is_array($auth)
      && \is_int($auth['idle_expires_at'] ?? null)
      && \is_int($auth['absolute_expires_at'] ?? null)
      && \min($auth['idle_expires_at'], $auth['absolute_expires_at']) <= $this->_runtime->now()
    ) {
      $this->invalidateAuthentication(false);
      return;
    }

    try {
      if (!\is_array($auth)) {
        throw SessionException::malformedRestoredState();
      }
      $validated = $this->validateAuthenticationPayload($auth);
      $this->adoptAuthentication($validated);
      $canonicalRoot['auth'] = $validated;
      $location = $this->restoreLocation($rootValue['location'] ?? null);
      if ($location !== null) {
        $canonicalRoot['location'] = $location;
      }
      $this->_values->assertSessionSize($canonicalRoot);
      $_SESSION[self::STORAGE_KEY] = $canonicalRoot;
    } catch (\Throwable $cause) {
      $this->_logger->warning('session.restore.rejected', ['exception' => $cause]);
      $this->invalidateAuthentication(true);
    }
  }

  /**
   * @return array{version:int,identity:array<string,string|int|float|bool|null>,access_group:string,access_rank:int,issued_at:int,idle_expires_at:int,absolute_expires_at:int}
   */
  private function buildAuthenticationPayload(object $user, int $lifetime):array {
    $properties = $this->publicProperties($user);
    $id = $this->normalizeId($properties['id'] ?? null);
    $uniqueId = $this->normalizeUniqueId($properties['uniqueid'] ?? null);
    [$group, $rank] = $this->normalizePrivilege($properties);

    $identity = $this->_values->projectIdentity($user, [
      'id' => $id,
      'uniqueid' => $uniqueId,
      'access_group' => $group->value,
      'access_rank' => $rank,
    ]);

    if ($lifetime <= 0) {
      $lifetime = $this->_config->defaultIdleLifetime;
    }
    $lifetime = \min($lifetime, $this->_config->maxIdleLifetime);
    $now = $this->_runtime->now();
    $absoluteExpiry = $now + $this->_config->absoluteLifetime;
    $idleExpiry = \min($now + $lifetime, $absoluteExpiry);

    return [
      'version' => self::AUTH_VERSION,
      'identity' => $identity,
      'access_group' => $group->value,
      'access_rank' => $rank,
      'issued_at' => $now,
      'idle_expires_at' => $idleExpiry,
      'absolute_expires_at' => $absoluteExpiry,
    ];
  }

  /**
   * @param array<mixed> $payload
   * @return array{version:int,identity:array<string,string|int|float|bool|null>,access_group:string,access_rank:int,issued_at:int,idle_expires_at:int,absolute_expires_at:int}
   */
  private function validateAuthenticationPayload(array $payload):array {
    if (
      ($payload['version'] ?? null) !== self::AUTH_VERSION
      || !\is_array($payload['identity'] ?? null)
      || !\is_string($payload['access_group'] ?? null)
      || !\is_int($payload['access_rank'] ?? null)
      || !\is_int($payload['issued_at'] ?? null)
      || !\is_int($payload['idle_expires_at'] ?? null)
      || !\is_int($payload['absolute_expires_at'] ?? null)
    ) {
      throw SessionException::malformedRestoredState();
    }

    $identity = $this->_values->validateStoredIdentity($payload['identity']);
    $id = $this->normalizeId($identity['id'] ?? null);
    $uniqueId = $this->normalizeUniqueId($identity['uniqueid'] ?? null);
    $group = AccessGroup::tryFrom($payload['access_group']);
    $rank = AccessRank::tryFrom($payload['access_rank']);
    if (
      $group === null
      || $group === AccessGroup::GUEST
      || $rank === null
      || $group->toRank() !== $rank
      || ($identity['access_group'] ?? null) !== $group->value
      || ($identity['access_rank'] ?? null) !== $rank->value
      || $identity['id'] !== $id
      || $identity['uniqueid'] !== $uniqueId
      || $payload['issued_at'] <= 0
      || $payload['issued_at'] > $payload['idle_expires_at']
      || $payload['issued_at'] > $payload['absolute_expires_at']
      || $payload['idle_expires_at'] > $payload['absolute_expires_at']
      || \min($payload['idle_expires_at'], $payload['absolute_expires_at']) <= $this->_runtime->now()
    ) {
      throw SessionException::malformedRestoredState();
    }

    return [
      'version' => self::AUTH_VERSION,
      'identity' => $identity,
      'access_group' => $group->value,
      'access_rank' => $rank->value,
      'issued_at' => $payload['issued_at'],
      'idle_expires_at' => $payload['idle_expires_at'],
      'absolute_expires_at' => $payload['absolute_expires_at'],
    ];
  }

  /**
   * @param array<string, mixed> $properties
   * @return array{0: AccessGroup, 1: int}
   */
  private function normalizePrivilege(array $properties):array {
    $hasGroup = \array_key_exists('access_group', $properties);
    $hasRank = \array_key_exists('access_rank', $properties);
    $group = $hasGroup ? $this->normalizeAccessGroup($properties['access_group']) : null;
    $rank = $hasRank ? $this->normalizeAccessRank($properties['access_rank']) : null;

    // A supplied value that does not normalize is a rejection, never a silent
    // fallback to the other field. Deriving the group from the rank when the
    // group was supplied but unusable would let the rank alone decide
    // privilege, which is exactly the escalation this class must prevent.
    if (($hasGroup && $group === null) || ($hasRank && $rank === null)) {
      throw new \InvalidArgumentException('The identity privilege is invalid.');
    }

    if ($group === null && $rank === null) {
      return [AccessGroup::USER, AccessRank::USER->value];
    }
    if ($group === null) {
      $group = AccessGroup::fromRank($rank);
    }
    if ($rank === null) {
      $rank = $group->toRank();
    }
    if ($group === AccessGroup::GUEST || $group->toRank() !== $rank) {
      throw new \InvalidArgumentException('The identity privilege is invalid.');
    }
    return [$group, $rank->value];
  }

  private function normalizeAccessGroup(mixed $value):?AccessGroup {
    if ($value instanceof AccessGroup) {
      return $value;
    }
    return \is_string($value) ? AccessGroup::tryFrom($value) : null;
  }

  private function normalizeAccessRank(mixed $value):?AccessRank {
    if ($value instanceof AccessRank) {
      return $value;
    }
    if (\is_string($value) && \preg_match('/^(?:0|[1-9][0-9]*)$/D', $value) === 1) {
      $value = (int)$value;
    }
    return \is_int($value) ? AccessRank::tryFrom($value) : null;
  }

  private function normalizeId(mixed $value):int|string {
    if (\is_int($value) && $value > 0) {
      return $value;
    }
    if (
      \is_string($value)
      && $value !== ''
      && \strlen($value) <= 128
      && \preg_match('//u', $value) === 1
      && \preg_match('/[\x00-\x1F\x7F]/', $value) !== 1
      && $value === \trim($value)
    ) {
      return $value;
    }
    throw new \InvalidArgumentException('The identity id is invalid.');
  }

  private function normalizeUniqueId(mixed $value):string {
    if (
      !\is_string($value)
      || $value === ''
      || \strlen($value) > 255
      || \preg_match('//u', $value) !== 1
      || \preg_match('/[\x00-\x1F\x7F]/', $value) === 1
      || $value !== \trim($value)
    ) {
      throw new \InvalidArgumentException('The identity uniqueid is invalid.');
    }
    return $value;
  }

  /**
   * @param array{version:int,identity:array<string,string|int|float|bool|null>,access_group:string,access_rank:int,issued_at:int,idle_expires_at:int,absolute_expires_at:int} $payload
   */
  private function adoptAuthentication(array $payload):void {
    $this->_identity = $payload['identity'];
    $this->_id = $this->normalizeId($payload['identity']['id']);
    $this->name = $this->normalizeUniqueId($payload['identity']['uniqueid']);
    $this->_access_group = AccessGroup::from($payload['access_group']);
    $this->_access_rank = $payload['access_rank'];
    $this->_idle_expires_at = $payload['idle_expires_at'];
    $this->_absolute_expires_at = $payload['absolute_expires_at'];
    $this->_expire = \min($this->_idle_expires_at, $this->_absolute_expires_at);
    $this->_logged_in = true;
    $this->syncUserView();
  }

  private function invalidateAuthentication(bool $recordError):void {
    $root = $this->root();
    unset($root['auth'], $root['location']);
    $_SESSION[self::STORAGE_KEY] = $root;
    $this->resetGuest();

    if ($recordError) {
      $this->addSafeError(
        'restore',
        self::RESTORE_INVALID,
        'Stored authentication was rejected.',
        AccessRank::GUEST->value
      );
    }

    if (
      $this->_runtime->status() === PHP_SESSION_ACTIVE
      && !$this->_runtime->headersSent()
      && !$this->_runtime->regenerateId(true)
    ) {
      $this->_logger->error('session.restore.rotation_failed', [
        'exception' => SessionException::regenerateFailed(),
      ]);
    }
  }

  private function resetGuest(bool $clearAttributes = false):void {
    $this->_logged_in = false;
    $this->_expire = 0;
    $this->_idle_expires_at = 0;
    $this->_absolute_expires_at = 0;
    $this->_id = null;
    $this->_identity = [];
    if ($clearAttributes) {
      $this->_attributes = [];
    }
    $this->_location = null;
    $this->_user = null;
    $this->_access_group = AccessGroup::GUEST;
    $this->_access_rank = AccessRank::GUEST->value;
    try {
      $this->name = 'GUEST_' . \bin2hex($this->_runtime->randomBytes(8));
    } catch (\Throwable) {
      $this->name = 'GUEST';
    }
  }

  private function syncUserView():void {
    $this->_user = $this->_logged_in
      ? (object)\array_replace($this->_identity, $this->_attributes)
      : null;
  }

  /** @return array<string, mixed> */
  private function root():array {
    $root = $_SESSION[self::STORAGE_KEY] ?? [];
    if (!\is_array($root)) {
      return [];
    }
    $safe = [];
    foreach ($root as $key => $value) {
      if (\is_string($key)) {
        $safe[$key] = $value;
      }
    }
    return $safe;
  }

  /** @return array<string, mixed> */
  private function validateAttributeBag(mixed $value):array {
    if ($value === null) {
      return [];
    }
    if (!\is_array($value)) {
      throw new \InvalidArgumentException('Invalid attribute storage.');
    }

    $safe = [];
    foreach ($value as $key => $item) {
      if (!\is_string($key)) {
        throw new \InvalidArgumentException('Invalid attribute storage.');
      }
      $this->assertMutableAttributeKey($key);
      $safe[$key] = $this->_values->normalizeValue($item);
    }
    return $safe;
  }

  /** @return array<string, mixed> */
  private function validateFlashBag(mixed $value):array {
    if ($value === null) {
      return [];
    }
    if (!\is_array($value)) {
      throw new \InvalidArgumentException('Invalid flash storage.');
    }
    $safe = [];
    foreach ($value as $key => $item) {
      if (!\is_string($key)) {
        throw new \InvalidArgumentException('Invalid flash storage.');
      }
      $this->_values->assertKey($key);
      $safe[$key] = $this->_values->normalizeValue($item);
    }
    return $safe;
  }

  private function assertMutableAttributeKey(string $key):void {
    $this->_values->assertKey($key);
    if (
      \in_array($key, self::RESERVED_ATTRIBUTE_KEYS, true)
      || \array_key_exists($key, $this->_identity)
    ) {
      throw new \InvalidArgumentException('Authentication fields cannot be changed through session storage.');
    }
  }

  /** @return array<string, mixed>|null */
  private function restoreLocation(mixed $value):?array {
    if (!\is_array($value)) {
      return null;
    }
    try {
      $location = [];
      foreach (self::LOCATION_FIELDS as $field) {
        $location[$field] = $this->_values->normalizeValue($value[$field] ?? null);
      }
      $this->_location = (object)$location;
      return $location;
    } catch (\Throwable) {
      $this->_location = null;
      return null;
    }
  }

  private function assertCsrfInput(string $formId, int $ttl):void {
    if (!$this->isValidFormId($formId)) {
      throw new \InvalidArgumentException('The CSRF form identifier is invalid.');
    }
    if ($ttl < 1 || $ttl > $this->_config->csrfMaxTtl) {
      throw new \InvalidArgumentException('The CSRF token lifetime is invalid.');
    }
  }

  private function isValidFormId(string $formId):bool {
    return $formId !== ''
      && \strlen($formId) <= $this->_config->csrfMaxFormIdLength
      && \preg_match('/^[A-Za-z0-9][A-Za-z0-9_.:-]*$/D', $formId) === 1;
  }

  /**
   * @return array<string, array<int, array{hash:string,expires_at:int,created_at:int}>>
   */
  private function pruneCsrfStore(mixed $value, int $now):array {
    if (!\is_array($value)) {
      return [];
    }

    $safe = [];
    foreach ($value as $formId => $entries) {
      if (!\is_string($formId) || !$this->isValidFormId($formId) || !\is_array($entries)) {
        continue;
      }
      foreach ($entries as $entry) {
        if (
          !\is_array($entry)
          || !\is_string($entry['hash'] ?? null)
          || \preg_match('/^[a-f0-9]{64}$/D', $entry['hash']) !== 1
          || !\is_int($entry['expires_at'] ?? null)
          || !\is_int($entry['created_at'] ?? null)
          || $entry['expires_at'] <= $now
          || $entry['created_at'] <= 0
        ) {
          continue;
        }
        $safe[$formId][] = [
          'hash' => $entry['hash'],
          'expires_at' => $entry['expires_at'],
          'created_at' => $entry['created_at'],
        ];
      }
      if (isset($safe[$formId])) {
        \usort(
          $safe[$formId],
          static fn(array $left, array $right):int => $left['created_at'] <=> $right['created_at']
        );
        $safe[$formId] = \array_slice(
          $safe[$formId],
          -$this->_config->csrfTokensPerForm
        );
      }
    }
    return $this->enforceGlobalCsrfCap($safe);
  }

  /**
   * @param array<string, array<int, array{hash:string,expires_at:int,created_at:int}>> $store
   * @return array<string, array<int, array{hash:string,expires_at:int,created_at:int}>>
   */
  private function enforceGlobalCsrfCap(array $store):array {
    while ($this->countCsrfTokens($store) > $this->_config->csrfMaxTokens) {
      $oldestForm = null;
      $oldestIndex = null;
      $oldestCreated = PHP_INT_MAX;
      foreach ($store as $formId => $entries) {
        foreach ($entries as $index => $entry) {
          if ($entry['created_at'] < $oldestCreated) {
            $oldestCreated = $entry['created_at'];
            $oldestForm = $formId;
            $oldestIndex = $index;
          }
        }
      }
      if ($oldestForm === null || $oldestIndex === null) {
        break;
      }
      unset($store[$oldestForm][$oldestIndex]);
      $store[$oldestForm] = \array_values($store[$oldestForm]);
      if ($store[$oldestForm] === []) {
        unset($store[$oldestForm]);
      }
    }
    return $store;
  }

  /** @param array<string, array<int, array{hash:string,expires_at:int,created_at:int}>> $store */
  private function countCsrfTokens(array $store):int {
    $count = 0;
    foreach ($store as $entries) {
      $count += \count($entries);
    }
    return $count;
  }

  private function iniBoolean(string $name):?bool {
    $value = $this->_runtime->ini($name);
    if ($value === false) {
      return null;
    }
    return \in_array(\strtolower($value), ['1', 'on', 'yes', 'true'], true);
  }

  private function iniInteger(string $name):int {
    $value = $this->_runtime->ini($name);
    if (!\is_string($value) || \preg_match('/^[0-9]+$/D', $value) !== 1) {
      return -1;
    }
    return (int)$value;
  }

  private function recordLoginRotationFailure(\Throwable $cause):void {
    $this->addSafeError(
      'login',
      self::LOGIN_ROTATION_FAILED,
      'The session identifier could not be rotated.',
      AccessRank::GUEST->value
    );
    $this->_logger->error('session.login.rotation_failed', ['exception' => $cause]);
  }

  private function addSafeError(
    string $context,
    int $code,
    string $message,
    int $minimumRank
  ):void {
    $this->traitAddError($context, $message, $minimumRank, $code, '[internal]', 1);
  }

  /** @return array<string, mixed> */
  private function publicProperties(object $object):array {
    $properties = [];
    foreach (\get_object_vars($object) as $key => $value) {
      if (\is_string($key)) {
        $properties[$key] = $value;
      }
    }
    return $properties;
  }

  private function clearErrorContext(string $context):void {
    $this->traitClearErrors($context);
  }
}
