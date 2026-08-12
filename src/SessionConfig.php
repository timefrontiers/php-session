<?php

declare(strict_types=1);

namespace TimeFrontiers;

/**
 * Immutable trusted-bootstrap configuration for Session.
 */
final readonly class SessionConfig {

  /** @var list<string> */
  public const DEFAULT_IDENTITY_FIELDS = [
    'name',
    'surname',
    'country_code',
    'avatar',
    'auth_version',
  ];

  public string $cookieName;
  public bool $externalRequestIsSecure;
  public bool $cookieSecure;
  public bool $cookieHttpOnly;
  public bool $cookiePartitioned;
  public string $cookieSameSite;
  public string $cookiePath;
  public ?string $cookieDomain;
  public int $cookieLifetime;
  public bool $strictMode;
  public bool $onlyCookies;
  public bool $allowInsecureDevelopment;
  public int $defaultIdleLifetime;
  public int $maxIdleLifetime;
  public int $absoluteLifetime;
  public int $maxExpiryExtension;
  public int $csrfMaxTtl;
  public int $csrfTokensPerForm;
  public int $csrfMaxTokens;
  public int $csrfMaxFormIdLength;
  /** @var list<string> */
  public array $identityFields;
  public ?\Closure $identityMapper;
  public int $maxIdentityFields;
  public int $maxStorageDepth;
  public int $maxStorageItems;
  public int $maxStringBytes;
  public int $maxValueBytes;
  public int $maxSessionBytes;
  public bool $locationEnabled;
  public bool $locationRequired;
  public ?\Closure $locationResolver;
  public SessionRuntimeInterface $runtime;

  /**
   * The external security boolean must come from trusted host/proxy bootstrap.
   * Session never derives it from request headers.
   *
   * @param list<string> $identityFields
   */
  public function __construct(
    string $cookieName = 'PHPSESSID',
    bool $externalRequestIsSecure = true,
    bool $cookieSecure = true,
    bool $cookieHttpOnly = true,
    bool $cookiePartitioned = false,
    string $cookieSameSite = 'Lax',
    string $cookiePath = '/',
    ?string $cookieDomain = null,
    int $cookieLifetime = 0,
    bool $strictMode = true,
    bool $onlyCookies = true,
    bool $allowInsecureDevelopment = false,
    int $defaultIdleLifetime = 1800,
    int $maxIdleLifetime = 86400,
    int $absoluteLifetime = 86400,
    int $maxExpiryExtension = 86400,
    int $csrfMaxTtl = 7200,
    int $csrfTokensPerForm = 5,
    int $csrfMaxTokens = 100,
    int $csrfMaxFormIdLength = 128,
    array $identityFields = self::DEFAULT_IDENTITY_FIELDS,
    ?callable $identityMapper = null,
    int $maxIdentityFields = 32,
    int $maxStorageDepth = 4,
    int $maxStorageItems = 128,
    int $maxStringBytes = 8192,
    int $maxValueBytes = 65536,
    int $maxSessionBytes = 262144,
    bool $locationEnabled = false,
    bool $locationRequired = false,
    ?callable $locationResolver = null,
    ?SessionRuntimeInterface $runtime = null
  ) {
    $sameSite = \ucfirst(\strtolower($cookieSameSite));
    $domain = $cookieDomain === '' ? null : $cookieDomain;

    if (
      \preg_match('/^[A-Za-z0-9._-]{1,128}$/D', $cookieName) !== 1
      || \preg_match('/^\/[^;\x00-\x1F\x7F]*$/D', $cookiePath) !== 1
      || !\in_array($sameSite, ['Lax', 'Strict', 'None'], true)
      || ($domain !== null && \preg_match('/^\.?[A-Za-z0-9.-]{1,253}$/D', $domain) !== 1)
      || $cookieLifetime < 0
      || $cookieLifetime > 31536000
      || $defaultIdleLifetime < 1
      || $maxIdleLifetime < $defaultIdleLifetime
      || $absoluteLifetime < $defaultIdleLifetime
      || $maxExpiryExtension < 1
      || $defaultIdleLifetime > 31536000
      || $maxIdleLifetime > 31536000
      || $absoluteLifetime > 31536000
      || $maxExpiryExtension > 31536000
      || $csrfMaxTtl < 1
      || $csrfTokensPerForm < 2
      || $csrfMaxTokens < $csrfTokensPerForm
      || $csrfMaxFormIdLength < 1
      || $maxIdentityFields < 7
      || $maxStorageDepth < 1
      || $maxStorageItems < 1
      || $maxStringBytes < 1
      || $maxValueBytes < $maxStringBytes
      || $maxSessionBytes < $maxValueBytes
      || $locationRequired && !$locationEnabled
      || $sameSite === 'None' && !$cookieSecure
      || $cookiePartitioned && !$cookieSecure
      || (!$cookieSecure || !$cookieHttpOnly || !$strictMode || !$onlyCookies) && !$allowInsecureDevelopment
      || !$externalRequestIsSecure && !$allowInsecureDevelopment
      || (!$externalRequestIsSecure && $cookieSecure)
    ) {
      throw SessionException::invalidConfiguration();
    }

    $validatedFields = [];
    foreach ($identityFields as $field) {
      if (
        \preg_match('/^[A-Za-z][A-Za-z0-9_]{0,63}$/D', $field) !== 1
        || \in_array($field, $validatedFields, true)
      ) {
        throw SessionException::invalidConfiguration();
      }
      $validatedFields[] = $field;
    }

    $this->cookieName = $cookieName;
    $this->externalRequestIsSecure = $externalRequestIsSecure;
    $this->cookieSecure = $cookieSecure;
    $this->cookieHttpOnly = $cookieHttpOnly;
    $this->cookiePartitioned = $cookiePartitioned;
    $this->cookieSameSite = $sameSite;
    $this->cookiePath = $cookiePath;
    $this->cookieDomain = $domain;
    $this->cookieLifetime = $cookieLifetime;
    $this->strictMode = $strictMode;
    $this->onlyCookies = $onlyCookies;
    $this->allowInsecureDevelopment = $allowInsecureDevelopment;
    $this->defaultIdleLifetime = $defaultIdleLifetime;
    $this->maxIdleLifetime = $maxIdleLifetime;
    $this->absoluteLifetime = $absoluteLifetime;
    $this->maxExpiryExtension = $maxExpiryExtension;
    $this->csrfMaxTtl = $csrfMaxTtl;
    $this->csrfTokensPerForm = $csrfTokensPerForm;
    $this->csrfMaxTokens = $csrfMaxTokens;
    $this->csrfMaxFormIdLength = $csrfMaxFormIdLength;
    $this->identityFields = $validatedFields;
    $this->identityMapper = $identityMapper === null ? null : \Closure::fromCallable($identityMapper);
    $this->maxIdentityFields = $maxIdentityFields;
    $this->maxStorageDepth = $maxStorageDepth;
    $this->maxStorageItems = $maxStorageItems;
    $this->maxStringBytes = $maxStringBytes;
    $this->maxValueBytes = $maxValueBytes;
    $this->maxSessionBytes = $maxSessionBytes;
    $this->locationEnabled = $locationEnabled;
    $this->locationRequired = $locationRequired;
    $this->locationResolver = $locationResolver === null ? null : \Closure::fromCallable($locationResolver);
    $this->runtime = $runtime ?? new NativeSessionRuntime();
  }

  public static function insecureDevelopment(
    string $cookieName = 'PHPSESSID',
    ?SessionRuntimeInterface $runtime = null
  ):self {
    return new self(
      cookieName: $cookieName,
      externalRequestIsSecure: false,
      cookieSecure: false,
      allowInsecureDevelopment: true,
      runtime: $runtime
    );
  }

  /** @return array{lifetime:int,path:string,domain:string,secure:bool,httponly:bool,samesite:'Lax'|'Strict'|'None',partitioned:bool} */
  public function cookieParameters():array {
    return [
      'lifetime' => $this->cookieLifetime,
      'path' => $this->cookiePath,
      'domain' => $this->cookieDomain ?? '',
      'secure' => $this->cookieSecure,
      'httponly' => $this->cookieHttpOnly,
      'samesite' => $this->cookieSameSite,
      'partitioned' => $this->cookiePartitioned,
    ];
  }

  /** @return array{expires:int,path:string,domain:string,secure:bool,httponly:bool,samesite:'Lax'|'Strict'|'None',partitioned:bool} */
  public function cookieOptions(int $expires):array {
    return [
      'expires' => $expires,
      'path' => $this->cookiePath,
      'domain' => $this->cookieDomain ?? '',
      'secure' => $this->cookieSecure,
      'httponly' => $this->cookieHttpOnly,
      'samesite' => $this->cookieSameSite,
      'partitioned' => $this->cookiePartitioned,
    ];
  }
}
