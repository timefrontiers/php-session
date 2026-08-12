<?php

declare(strict_types=1);

namespace TimeFrontiers;

/** @internal */
final class SessionValuePolicy {

  private const CORE_IDENTITY_FIELDS = [
    'id',
    'uniqueid',
    'access_group',
    'access_rank',
  ];

  private const SENSITIVE_FRAGMENTS = [
    'password',
    'passwd',
    'pwd',
    'hash',
    'token',
    'secret',
    'credential',
    'authorization',
    'cookie',
    'connection',
    'private_key',
  ];

  public function __construct(private SessionConfig $config) {}

  /**
   * Build the bounded plain identity retained by user().
   *
   * @param array{id:int|string,uniqueid:string,access_group:string,access_rank:int} $core
   * @return array<string, string|int|float|bool|null>
   */
  public function projectIdentity(object $user, array $core):array {
    $properties = \get_object_vars($user);
    if (\count($properties) > $this->config->maxStorageItems) {
      throw new \InvalidArgumentException('The identity projection is too large.');
    }

    // Inspect every public input field, even fields that are not retained. This
    // prevents a full database/provider object containing secrets or unsafe
    // graphs from being mistaken for a bounded authentication projection.
    foreach ($properties as $name => $value) {
      $this->assertKey($name);
      $this->normalizeValue($value);
    }

    $identity = $core;
    foreach ($this->config->identityFields as $field) {
      if (!\array_key_exists($field, $properties)) {
        continue;
      }

      $identity[$field] = $this->normalizeIdentityField($field, $properties[$field]);
    }

    if ($this->config->identityMapper !== null) {
      try {
        $extra = ($this->config->identityMapper)(clone $user, (object)$identity);
      } catch (\Throwable $cause) {
        throw new \InvalidArgumentException('The identity projection is invalid.', 0, $cause);
      }

      if ($extra instanceof \stdClass) {
        $extra = \get_object_vars($extra);
      }
      if (!\is_array($extra)) {
        throw new \InvalidArgumentException('The identity projection is invalid.');
      }

      foreach ($extra as $name => $value) {
        if (!\is_string($name)) {
          throw new \InvalidArgumentException('The identity projection is invalid.');
        }
        $this->assertKey($name);
        if (\array_key_exists($name, $identity)) {
          throw new \InvalidArgumentException('The identity projection is invalid.');
        }
        $identity[$name] = $this->normalizeIdentityScalar($value);
      }
    }

    return $this->validateStoredIdentity($identity);
  }

  /**
   * @param array<mixed> $identity
   * @return array<string, string|int|float|bool|null>
   */
  public function validateStoredIdentity(array $identity):array {
    if (
      \count($identity) > $this->config->maxIdentityFields
      || \array_diff(self::CORE_IDENTITY_FIELDS, \array_keys($identity)) !== []
    ) {
      throw new \InvalidArgumentException('The identity projection is invalid.');
    }

    $safe = [];
    foreach ($identity as $name => $value) {
      if (!\is_string($name)) {
        throw new \InvalidArgumentException('The identity projection is invalid.');
      }
      $this->assertKey($name, \in_array($name, self::CORE_IDENTITY_FIELDS, true));
      $safe[$name] = $this->normalizeIdentityScalar($value);
    }

    $this->assertValueSize($safe);
    return $safe;
  }

  public function normalizeValue(mixed $value):mixed {
    $items = 0;
    $activeReferences = [];
    $safe = $this->walkValue($value, 0, $items, $activeReferences);
    $this->assertValueSize($safe);
    return $safe;
  }

  public function assertKey(string $key, bool $allowReservedIdentity = false):void {
    if (\preg_match('/^[A-Za-z][A-Za-z0-9_.:-]{0,63}$/D', $key) !== 1) {
      throw new \InvalidArgumentException('The session key is invalid.');
    }

    if (!$allowReservedIdentity && $this->isSensitiveKey($key)) {
      throw new \InvalidArgumentException('Sensitive values cannot be stored in a session.');
    }
  }

  public function isSensitiveKey(string $key):bool {
    $normalized = \strtolower($key);
    if ($normalized === 'conn' || \str_starts_with($normalized, 'conn_')) {
      return true;
    }
    foreach (self::SENSITIVE_FRAGMENTS as $fragment) {
      if (\str_contains($normalized, $fragment)) {
        return true;
      }
    }
    return false;
  }

  /** @param array<mixed> $sessionData */
  public function assertSessionSize(array $sessionData):void {
    if (\strlen(\serialize($sessionData)) > $this->config->maxSessionBytes) {
      throw new \InvalidArgumentException('The session storage limit was exceeded.');
    }
  }

  private function normalizeIdentityField(string $field, mixed $value):string|int|float|bool|null {
    return match ($field) {
      'name', 'surname' => $this->normalizeDisplayString($value, 255),
      'avatar' => $this->normalizeDisplayString($value, 2048),
      'country_code' => $this->normalizeCountryCode($value),
      'auth_version' => $this->normalizeAuthVersion($value),
      default => $this->normalizeIdentityScalar($value),
    };
  }

  private function normalizeIdentityScalar(mixed $value):string|int|float|bool|null {
    if ($value instanceof \BackedEnum) {
      $value = $value->value;
    }
    if (\is_string($value)) {
      $this->assertString($value);
      return $value;
    }
    if (\is_float($value) && !\is_finite($value)) {
      throw new \InvalidArgumentException('The identity projection is invalid.');
    }
    if (\is_int($value) || \is_float($value) || \is_bool($value) || $value === null) {
      return $value;
    }
    throw new \InvalidArgumentException('The identity projection is invalid.');
  }

  /**
   * Optional display fields are enrichment, not credentials. An unusable value
   * is dropped to null so that a blank surname or an empty country column
   * cannot deny authentication to an otherwise valid identity. Size and
   * encoding limits are still enforced ahead of this by the full-object scan
   * in projectIdentity().
   */
  private function normalizeDisplayString(mixed $value, int $maximum):?string {
    if (!\is_string($value)) {
      return null;
    }
    $value = \trim($value);
    if (
      $value === ''
      || \strlen($value) > $maximum
      || \preg_match('//u', $value) !== 1
      || \preg_match('/[\x00-\x1F\x7F]/', $value) === 1
    ) {
      return null;
    }
    return $value;
  }

  private function normalizeCountryCode(mixed $value):?string {
    if (!\is_string($value) || \preg_match('/^[A-Za-z]{2}$/D', $value) !== 1) {
      return null;
    }
    return \strtoupper($value);
  }

  private function normalizeAuthVersion(mixed $value):int {
    if (\is_string($value) && \preg_match('/^(?:0|[1-9][0-9]*)$/D', $value) === 1) {
      $value = (int)$value;
    }
    if (!\is_int($value) || $value < 0) {
      throw new \InvalidArgumentException('The identity projection is invalid.');
    }
    return $value;
  }

  /**
   * @param array<string, true> $activeReferences
   */
  private function walkValue(
    mixed &$value,
    int $depth,
    int &$items,
    array &$activeReferences
  ):mixed {
    if (++$items > $this->config->maxStorageItems || $depth > $this->config->maxStorageDepth) {
      throw new \InvalidArgumentException('The session value is too large or deeply nested.');
    }

    if ($value instanceof \BackedEnum) {
      $backing = $value->value;
      return $this->walkValue($backing, $depth, $items, $activeReferences);
    }
    if (\is_string($value)) {
      $this->assertString($value);
      return $value;
    }
    if (\is_float($value) && !\is_finite($value)) {
      throw new \InvalidArgumentException('The session value is invalid.');
    }
    if (\is_int($value) || \is_float($value) || \is_bool($value) || $value === null) {
      return $value;
    }
    if (\is_resource($value) || \is_object($value)) {
      throw new \InvalidArgumentException('Objects and resources cannot be stored in a session value.');
    }
    if (!\is_array($value)) {
      throw new \InvalidArgumentException('The session value is invalid.');
    }

    $safe = [];
    foreach (\array_keys($value) as $key) {
      if (\is_string($key)) {
        $this->assertKey($key);
      }

      $reference = \ReflectionReference::fromArrayElement($value, $key);
      $referenceId = $reference?->getId();
      if ($referenceId !== null && isset($activeReferences[$referenceId])) {
        throw new \InvalidArgumentException('Cyclic values cannot be stored in a session.');
      }
      if ($referenceId !== null) {
        $activeReferences[$referenceId] = true;
      }

      $child =& $value[$key];
      $safe[$key] = $this->walkValue($child, $depth + 1, $items, $activeReferences);
      unset($child);

      if ($referenceId !== null) {
        unset($activeReferences[$referenceId]);
      }
    }

    return $safe;
  }

  private function assertString(string $value):void {
    if (
      \strlen($value) > $this->config->maxStringBytes
      || \preg_match('//u', $value) !== 1
    ) {
      throw new \InvalidArgumentException('The session string value is invalid or too large.');
    }
  }

  private function assertValueSize(mixed $value):void {
    if (\strlen(\serialize($value)) > $this->config->maxValueBytes) {
      throw new \InvalidArgumentException('The session value exceeds the storage limit.');
    }
  }
}
