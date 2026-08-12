<?php

declare(strict_types=1);

namespace TimeFrontiers\Tests;

use TimeFrontiers\SessionConfig;
use TimeFrontiers\Tests\Support\SessionTestCase;

final class SessionCsrfTest extends SessionTestCase {

  public function testMultipleTabsCanHoldIndependentTokensForOneForm():void {
    $session = $this->session();
    $first = $session->generateCSRFToken('profile-form');
    ++$this->runtime->timestamp;
    $second = $session->generateCSRFToken('profile-form');

    self::assertNotSame($first, $second);
    self::assertTrue($session->validateCSRFToken('profile-form', $first));
    self::assertTrue($session->validateCSRFToken('profile-form', $second));
  }

  public function testWrongTokenDoesNotConsumeValidToken():void {
    $session = $this->session();
    $token = $session->generateCSRFToken('checkout');

    self::assertFalse($session->validateCSRFToken('checkout', 'wrong-token'));
    self::assertTrue($session->validateCSRFToken('checkout', $token));
  }

  public function testSuccessfulTokenIsSingleUse():void {
    $session = $this->session();
    $token = $session->generateCSRFToken('contact');

    self::assertTrue($session->validateCSRFToken('contact', $token));
    self::assertFalse($session->validateCSRFToken('contact', $token));
  }

  public function testSuccessfulLoginDropsPreAuthenticationTokens():void {
    $session = $this->session();
    $guestToken = $session->generateCSRFToken('profile');
    $session->set('return_to', '/dashboard');

    self::assertTrue($session->login($this->user()));
    self::assertFalse($session->validateCSRFToken('profile', $guestToken));
    self::assertSame('/dashboard', $session->get('return_to'));

    $authenticatedToken = $session->generateCSRFToken('profile');
    self::assertTrue($session->validateCSRFToken('profile', $authenticatedToken));
  }

  public function testFailedLoginRotationPreservesPreAuthenticationToken():void {
    $session = $this->session();
    $guestToken = $session->generateCSRFToken('profile');
    $this->runtime->regenerationSucceeds = false;

    self::assertFalse($session->login($this->user()));
    self::assertTrue($session->validateCSRFToken('profile', $guestToken));
  }

  public function testExpiryEqualityIsRejected():void {
    $session = $this->session();
    $token = $session->generateCSRFToken('contact', 10);
    $this->runtime->timestamp += 10;

    self::assertFalse($session->validateCSRFToken('contact', $token));
  }

  public function testTtlAndFormIdentifiersAreBounded():void {
    $session = $this->session();

    foreach ([0, -1, 7201] as $ttl) {
      try {
        $session->generateCSRFToken('form', $ttl);
        self::fail('Expected TTL rejection.');
      } catch (\InvalidArgumentException) {}
    }

    $this->expectException(\InvalidArgumentException::class);
    $session->generateCSRFToken('../bad form');
  }

  public function testPerFormAndGlobalCapsEvictOldestTokens():void {
    $config = new SessionConfig(
      csrfTokensPerForm: 2,
      csrfMaxTokens: 3,
      runtime: $this->runtime
    );
    $session = $this->session($config);
    $first = $session->generateCSRFToken('a');
    ++$this->runtime->timestamp;
    $second = $session->generateCSRFToken('a');
    ++$this->runtime->timestamp;
    $third = $session->generateCSRFToken('a');
    ++$this->runtime->timestamp;
    $fourth = $session->generateCSRFToken('b');
    ++$this->runtime->timestamp;
    $fifth = $session->generateCSRFToken('c');

    self::assertFalse($session->validateCSRFToken('a', $first));
    self::assertFalse($session->validateCSRFToken('a', $second));
    self::assertTrue($session->validateCSRFToken('a', $third));
    self::assertTrue($session->validateCSRFToken('b', $fourth));
    self::assertTrue($session->validateCSRFToken('c', $fifth));
  }

  public function testMalformedStoredShapesArePrunedWithoutWarnings():void {
    $session = $this->session();
    $root = $this->storedRoot();
    $root['csrf'] = [
      'form' => [['hash' => [], 'expires_at' => 'later']],
    ];
    $_SESSION['_timefrontiers_session'] = $root;

    self::assertFalse($session->validateCSRFToken('form', 'anything'));
    self::assertSame([], $this->storedRoot()['csrf']);
  }

  public function testCsrfFieldEscapesNameUsingUtf8SafeFlags():void {
    $session = $this->session();
    $html = $session->csrfField('form', 'field" onfocus="bad');

    self::assertStringContainsString('field&quot; onfocus=&quot;bad', $html);
    self::assertStringNotContainsString('onfocus="bad', $html);
  }

  public function testLegacyAliasesEmitDeprecationsAndDelegate():void {
    $session = $this->session();
    $messages = [];
    \set_error_handler(static function(int $level, string $message) use (&$messages):bool {
      if ($level === E_USER_DEPRECATED) {
        $messages[] = $message;
        return true;
      }
      return false;
    });
    try {
      $token = $session->createCSRFtoken('legacy');
      self::assertTrue($session->isValidCSRFtoken('legacy', $token));
    } finally {
      \restore_error_handler();
    }

    self::assertCount(2, $messages);
  }
}
