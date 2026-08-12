<?php

declare(strict_types=1);

namespace TimeFrontiers\Tests;

use Psr\Log\AbstractLogger;
use TimeFrontiers\Session;
use TimeFrontiers\SessionConfig;
use TimeFrontiers\Tests\Support\SessionTestCase;

final class SessionErrorLocationTest extends SessionTestCase {

  public function testErrorsAreInstanceIsolatedAndStaticClearRemainsCompatible():void {
    $first = $this->session();
    self::assertFalse($first->login((object)['uniqueid' => 'missing-id']));
    $second = $this->session();

    self::assertTrue($first->hasErrors());
    self::assertFalse($second->hasErrors());
    Session::clearErrors();
    self::assertFalse($first->hasErrors());
    self::assertFalse($second->hasErrors());
  }

  public function testInstanceClearCanTargetOneContextWithoutAffectingOthers():void {
    $config = new SessionConfig(
      locationEnabled: true,
      locationRequired: true,
      locationResolver: static fn():never => throw new \RuntimeException('provider secret'),
      runtime: $this->runtime
    );
    $session = $this->session($config);
    $other = $this->session($config);

    self::assertFalse($session->login((object)['uniqueid' => 'missing-id']));
    self::assertFalse($session->refreshLocation());
    self::assertFalse($other->login((object)['uniqueid' => 'missing-id']));
    self::assertArrayHasKey('login', $session->getErrors());
    self::assertArrayHasKey('location', $session->getErrors());

    $session->clearInstanceErrors('login');
    self::assertArrayNotHasKey('login', $session->getErrors());
    self::assertArrayHasKey('location', $session->getErrors());
    self::assertTrue($other->hasErrors());

    $session->clearInstanceErrors();
    self::assertFalse($session->hasErrors());
    self::assertTrue($other->hasErrors());
  }

  public function testIncidentalTraitHelpersAreNotPublicApi():void {
    $class = new \ReflectionClass(Session::class);

    self::assertFalse($class->getMethod('errorCount')->isPublic());
    self::assertFalse($class->getMethod('firstError')->isPublic());
    self::assertFalse($class->getMethod('errorMessages')->isPublic());
    self::assertTrue($class->getMethod('clearInstanceErrors')->isPublic());
  }

  public function testErrorsUseCanonicalSafeTuples():void {
    $session = $this->session();
    $session->login((object)['uniqueid' => 'missing-id']);
    $error = $session->getErrors()['login'][0];

    self::assertCount(5, $error);
    self::assertSame('[internal]', $error[3]);
    self::assertSame(1, $error[4]);
    self::assertStringNotContainsString('missing-id', $error[2]);
  }

  public function testOperationBoundaryClearsPreviousContextErrors():void {
    $session = $this->session();
    self::assertFalse($session->login((object)['uniqueid' => 'missing-id']));
    self::assertTrue($session->hasErrors());

    self::assertTrue($session->login($this->user()));
    self::assertFalse($session->hasErrors());
  }

  public function testLocationIsNotCoupledToLogin():void {
    $session = $this->session();

    self::assertTrue($session->login($this->user()));
    self::assertNull($session->location());
    self::assertFalse($session->hasErrors());
  }

  public function testOptionalLocationFailureDoesNotBecomeSessionError():void {
    $logger = new class extends AbstractLogger {
      /** @var list<array{level:mixed,message:string,context:array<mixed>}> */
      public array $records = [];
      /** @param array<array-key, mixed> $context */
      public function log($level, string|\Stringable $message, array $context = []):void {
        $this->records[] = ['level' => $level, 'message' => (string)$message, 'context' => $context];
      }
    };
    $config = new SessionConfig(
      locationEnabled: true,
      locationResolver: static fn():never => throw new \RuntimeException('provider secret'),
      runtime: $this->runtime
    );
    $session = new Session($logger, $config);

    self::assertTrue($session->login($this->user()));
    self::assertFalse($session->refreshLocation());
    self::assertFalse($session->hasErrors());
    $failure = \array_values(\array_filter(
      $logger->records,
      static fn(array $record):bool => $record['message'] === 'session.location.failed'
    ));
    self::assertCount(1, $failure);
    self::assertInstanceOf(\RuntimeException::class, $failure[0]['context']['exception']);
  }

  public function testRequiredLocationFailureAddsOnlyStableError():void {
    $config = new SessionConfig(
      locationEnabled: true,
      locationRequired: true,
      locationResolver: static fn():never => throw new \RuntimeException('provider secret'),
      runtime: $this->runtime
    );
    $session = $this->session($config);

    self::assertTrue($session->login($this->user()));
    self::assertFalse($session->refreshLocation());
    self::assertTrue($session->isLoggedIn());
    self::assertStringNotContainsString(
      'provider secret',
      $session->getErrors()['location'][0][2]
    );
  }

  public function testSuccessfulLocationIsBoundedAndRestored():void {
    $config = new SessionConfig(
      locationEnabled: true,
      locationResolver: static fn():object => (object)[
        'ip' => '192.0.2.1',
        'country' => 'Nigeria',
        'country_code' => 'NG',
        'latitude' => 6.5,
        'longitude' => 3.3,
        'ignored' => 'not stored',
      ],
      runtime: $this->runtime
    );
    $session = $this->session($config);

    self::assertTrue($session->refreshLocation());
    $location = (array)$session->location();
    self::assertSame('NG', $location['country_code']);
    self::assertArrayNotHasKey('ignored', $location);

    $restored = $this->session($config);
    self::assertSame('Nigeria', ((array)$restored->location())['country']);
  }
}
