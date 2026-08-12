<?php

declare(strict_types=1);

namespace TimeFrontiers\Tests;

use TimeFrontiers\Session;
use TimeFrontiers\SessionConfig;
use TimeFrontiers\SessionException;
use TimeFrontiers\Tests\Support\SessionTestCase;

final class SessionBootstrapTest extends SessionTestCase {

  public function testInactiveSessionIsConfiguredBeforeStart():void {
    $session = $this->session();

    self::assertFalse($session->isLoggedIn());
    self::assertSame(PHP_SESSION_ACTIVE, $this->runtime->status());
    self::assertSame('1', $this->runtime->iniValues['session.use_strict_mode']);
    self::assertSame('1', $this->runtime->iniValues['session.use_only_cookies']);
    self::assertSame('86400', $this->runtime->iniValues['session.gc_maxlifetime']);
    self::assertTrue($this->runtime->params['secure']);
  }

  public function testMatchingActiveSessionIsAdopted():void {
    $first = $this->session();
    $second = new Session(config: $this->config);

    self::assertFalse($first->isLoggedIn());
    self::assertFalse($second->isLoggedIn());
  }

  public function testMismatchedActiveSessionIsRejected():void {
    $this->session();
    $this->runtime->params['secure'] = false;

    $this->expectException(SessionException::class);
    $this->expectExceptionCode(SessionException::CONFIGURATION_AFTER_START);
    new Session(config: $this->config);
  }

  public function testHeadersSentPreventsStartingSession():void {
    $this->runtime->headersHaveBeenSent = true;

    $this->expectException(SessionException::class);
    $this->expectExceptionCode(SessionException::HEADERS_ALREADY_SENT);
    $this->session();
  }

  public function testStartFailureThrowsStableException():void {
    $this->runtime->startSucceeds = false;

    $this->expectException(SessionException::class);
    $this->expectExceptionCode(SessionException::START_FAILED);
    $this->session();
  }

  public function testRequestHeadersNeverInfluenceCookieSecurity():void {
    $_SERVER['HTTPS'] = 'off';
    $_SERVER['HTTP_X_FORWARDED_PROTO'] = 'http';
    $this->session();

    self::assertTrue($this->runtime->params['secure']);
  }
}
