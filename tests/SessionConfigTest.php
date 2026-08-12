<?php

declare(strict_types=1);

namespace TimeFrontiers\Tests;

use PHPUnit\Framework\TestCase;
use TimeFrontiers\SessionConfig;
use TimeFrontiers\SessionException;
use TimeFrontiers\Tests\Support\FakeSessionRuntime;

final class SessionConfigTest extends TestCase {

  public function testProductionDefaultsAreSecureAndExplicit():void {
    $config = new SessionConfig(runtime: new FakeSessionRuntime());

    self::assertTrue($config->externalRequestIsSecure);
    self::assertTrue($config->cookieSecure);
    self::assertTrue($config->cookieHttpOnly);
    self::assertTrue($config->strictMode);
    self::assertTrue($config->onlyCookies);
    self::assertSame('Lax', $config->cookieSameSite);
  }

  public function testInsecureCookiesRequireDevelopmentFactory():void {
    $this->expectException(SessionException::class);
    new SessionConfig(cookieSecure: false, runtime: new FakeSessionRuntime());
  }

  public function testDevelopmentFactoryIsExplicitlyInsecure():void {
    $config = SessionConfig::insecureDevelopment(runtime: new FakeSessionRuntime());

    self::assertFalse($config->externalRequestIsSecure);
    self::assertFalse($config->cookieSecure);
    self::assertTrue($config->allowInsecureDevelopment);
  }

  public function testSameSiteNoneRequiresSecureCookie():void {
    $this->expectException(SessionException::class);
    new SessionConfig(
      cookieSecure: false,
      cookieSameSite: 'None',
      allowInsecureDevelopment: true,
      runtime: new FakeSessionRuntime()
    );
  }

  public function testLocationCannotBeRequiredWhenDisabled():void {
    $this->expectException(SessionException::class);
    new SessionConfig(locationRequired: true, runtime: new FakeSessionRuntime());
  }
}
