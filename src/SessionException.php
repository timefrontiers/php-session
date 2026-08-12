<?php

declare(strict_types=1);

namespace TimeFrontiers;

/**
 * Stable, non-sensitive failures raised by the session boundary.
 */
final class SessionException extends \RuntimeException {

  public const CONFIGURATION_INVALID = 1001;
  public const CONFIGURATION_AFTER_START = 1002;
  public const HEADERS_ALREADY_SENT = 1003;
  public const START_FAILED = 1004;
  public const REGENERATE_FAILED = 1005;
  public const MALFORMED_RESTORED_STATE = 1006;
  public const DESTROY_FAILED = 1007;

  public static function invalidConfiguration():self {
    return new self('The session configuration is invalid.', self::CONFIGURATION_INVALID);
  }

  public static function configurationAfterStart():self {
    return new self(
      'The active session does not match the required configuration.',
      self::CONFIGURATION_AFTER_START
    );
  }

  public static function headersAlreadySent():self {
    return new self(
      'Session headers cannot be changed after output has started.',
      self::HEADERS_ALREADY_SENT
    );
  }

  public static function startFailed():self {
    return new self('Failed to start the session.', self::START_FAILED);
  }

  public static function regenerateFailed():self {
    return new self('Failed to rotate the session identifier.', self::REGENERATE_FAILED);
  }

  public static function malformedRestoredState():self {
    return new self(
      'Stored authentication state is invalid.',
      self::MALFORMED_RESTORED_STATE
    );
  }

  public static function destructionFailed():self {
    return new self('Failed to completely destroy the session.', self::DESTROY_FAILED);
  }

  /**
   * Backward-compatible factory retained for callers that used v1.0 directly.
   */
  public static function invalidState(string $message = ''):self {
    return self::malformedRestoredState();
  }
}
