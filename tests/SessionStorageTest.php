<?php

declare(strict_types=1);

namespace TimeFrontiers\Tests;

use TimeFrontiers\SessionConfig;
use TimeFrontiers\Tests\Support\SessionTestCase;

final class SessionStorageTest extends SessionTestCase {

  public function testDefaultIdentityProjectionIsBounded():void {
    $user = $this->user(['harmless_but_unapproved' => 'ignored']);
    $session = $this->session();

    self::assertTrue($session->login($user));
    $identity = (array)$session->user();
    self::assertArrayNotHasKey('harmless_but_unapproved', $identity);
    self::assertSame('Ada', $identity['name']);
    self::assertSame(3, $identity['auth_version']);
  }

  public function testExplicitMapperCanAddSafeScalarFields():void {
    $config = new SessionConfig(
      identityMapper: static fn(object $source, object $base):array => [
        'theme' => ((array)$source)['theme'],
      ],
      runtime: $this->runtime
    );
    $session = $this->session($config);

    self::assertTrue($session->login($this->user(['theme' => 'dark'])));
    self::assertSame('dark', ((array)$session->user())['theme']);
  }

  public function testSensitiveIdentityFieldsAreRejected():void {
    foreach (['password', 'password_hash', 'api_token', 'connection'] as $field) {
      $_SESSION = [];
      $session = $this->session();
      $user = $this->user([$field => 'must-not-persist']);
      self::assertFalse($session->login($user));
      self::assertFalse($session->isLoggedIn());
    }
  }

  public function testClosureResourceAndUnsupportedObjectAreRejected():void {
    $resource = \fopen('php://memory', 'rb');
    self::assertIsResource($resource);

    foreach ([static fn():bool => true, $resource, new \stdClass()] as $value) {
      $_SESSION = [];
      $session = $this->session();
      $user = $this->user(['extra' => $value]);
      self::assertFalse($session->login($user));
    }
    \fclose($resource);
  }

  public function testCyclicAndDeepArraysAreRejected():void {
    $cycle = [];
    $cycle['self'] =& $cycle;
    $deep = ['a' => ['b' => ['c' => ['d' => ['e' => 'too deep']]]]];

    foreach ([$cycle, $deep] as $value) {
      $_SESSION = [];
      $session = $this->session();
      self::assertFalse($session->login($this->user(['extra' => $value])));
    }
  }

  public function testSetGetRemoveAndAllUseSeparateBoundedAttributes():void {
    $session = $this->session();
    self::assertTrue($session->login($this->user()));

    $session->set('theme', ['mode' => 'dark', 'contrast' => 2]);
    self::assertTrue($session->has('theme'));
    $theme = $session->get('theme');
    self::assertIsArray($theme);
    self::assertSame('dark', $theme['mode']);
    self::assertSame('Ada', $session->get('name'));
    self::assertArrayHasKey('id', $session->all());
    self::assertArrayHasKey('theme', $session->all());
    $userView = (array)$session->user();
    self::assertIsArray($userView['theme']);
    self::assertSame('dark', $userView['theme']['mode']);

    $session->remove('theme');
    self::assertFalse($session->has('theme'));
  }

  public function testNullCountsAsPresent():void {
    $session = $this->session();
    $session->set('nullable', null);
    $session->flash('notice', null);

    self::assertTrue($session->has('nullable'));
    self::assertNull($session->get('nullable', 'fallback'));
    self::assertTrue($session->hasFlash('notice'));
    self::assertNull($session->getFlash('notice', 'fallback'));
    self::assertFalse($session->hasFlash('notice'));
  }

  public function testAuthenticationFieldsCannotBeMutatedBySetOrRemove():void {
    $session = $this->session();
    self::assertTrue($session->login($this->user()));

    try {
      $session->set('access_rank', 14);
      self::fail('Expected reserved-field rejection.');
    } catch (\InvalidArgumentException) {
      self::assertSame(1, $session->access_rank());
    }

    $this->expectException(\InvalidArgumentException::class);
    $session->remove('id');
  }

  public function testSetAndFlashRejectUnsafeValuesAndSensitiveKeys():void {
    $session = $this->session();

    foreach ([static fn():bool => true, INF, \str_repeat('x', 9000)] as $unsafe) {
      try {
        $session->set('preference', $unsafe);
        self::fail('Expected unsafe session value rejection.');
      } catch (\InvalidArgumentException) {
        self::assertFalse($session->has('preference'));
      }
    }

    $this->expectException(\InvalidArgumentException::class);
    $session->flash('reset_token', 'secret');
  }

  public function testUnusableOptionalDisplayFieldsDegradeInsteadOfDenyingLogin():void {
    $session = $this->session();

    self::assertTrue($session->login($this->user([
      'country_code' => '',
      'surname' => '   ',
      'avatar' => 123,
    ])));
    self::assertTrue($session->isLoggedIn());
    $identity = (array)$session->user();
    self::assertNull($identity['country_code']);
    self::assertNull($identity['surname']);
    self::assertNull($identity['avatar']);
    self::assertSame('Ada', $identity['name']);
  }

  public function testLegacyStateMigratesOnceAndLeavesApplicationRootKeysAlone():void {
    $_SESSION['user'] = (object)['id' => 42];
    $_SESSION['access_rank'] = 14;

    $migrating = $this->session();
    self::assertFalse($migrating->isLoggedIn());
    self::assertArrayNotHasKey('user', $_SESSION);
    self::assertArrayNotHasKey('access_rank', $_SESSION);

    self::assertTrue($migrating->login($this->user()));

    // Application code owning an unrelated root key must not be mistaken for
    // v1.0 residue and silently sign the user out.
    $_SESSION['name'] = 'an application value';
    $_SESSION['location'] = ['anything'];

    $next = $this->session();
    self::assertTrue($next->isLoggedIn());
    self::assertSame(42, $next->id());
    self::assertSame('an application value', $_SESSION['name']);
  }

  public function testOversizedStoredBagIsDiscardedWithoutThrowingFromConstructor():void {
    $oversized = [];
    for ($index = 0; $index < 40; ++$index) {
      $oversized['k' . $index] = \str_repeat('a', 8000);
    }
    $_SESSION['_timefrontiers_session'] = ['attributes' => $oversized];

    $session = $this->session();

    self::assertFalse($session->isLoggedIn());
    self::assertSame([], $session->all());
    self::assertTrue($session->hasErrors());
  }

  public function testFlashIsPullUntilReadAcrossRequests():void {
    $session = $this->session();
    $session->flash('success', 'Saved');

    $next = $this->session();
    self::assertTrue($next->hasFlash('success'));
    self::assertSame('Saved', $next->getFlash('success'));
    self::assertFalse($next->hasFlash('success'));
  }
}
