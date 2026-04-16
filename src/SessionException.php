<?php

declare(strict_types=1);

namespace TimeFrontiers;

/**
 * Exception thrown when session operations fail.
 */
class SessionException extends \RuntimeException {

  /**
   * Create exception for session start failure.
   */
  public static function startFailed():self {
    return new self('Failed to start session.');
  }

  /**
   * Create exception for invalid session state.
   */
  public static function invalidState(string $message):self {
    return new self("Invalid session state: {$message}");
  }

  /**
   * Create exception for session regeneration failure.
   */
  public static function regenerateFailed():self {
    return new self('Failed to regenerate session ID.');
  }
}
