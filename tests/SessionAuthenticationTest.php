<?php

declare(strict_types=1);

namespace TimeFrontiers\Tests;

use TimeFrontiers\AccessGroup;
use TimeFrontiers\AccessRank;
use TimeFrontiers\Session;
use TimeFrontiers\Tests\Support\SessionTestCase;

final class SessionAuthenticationTest extends SessionTestCase {

  public function testGuestDefaultsAreFailClosed():void {
    $session = $this->session();

    self::assertFalse($session->isLoggedIn());
    self::assertNull($session->id());
    self::assertNull($session->user());
    self::assertSame(AccessGroup::GUEST, $session->access_group());
    self::assertSame(AccessRank::GUEST->value, $session->access_rank());
    self::assertStringStartsWith('GUEST_', $session->name);
  }

  public function testLoginRotatesBeforeCommittingVersionedPayload():void {
    $session = $this->session();
    $before = $this->runtime->id();

    self::assertTrue($session->login($this->user()));
    self::assertNotSame($before, $this->runtime->id());
    $auth = $this->storedAuth();
    self::assertSame(1, $auth['version']);
    self::assertSame('USER', $auth['access_group']);
    self::assertIsArray($auth['identity']);
    self::assertIsString($auth['identity']['access_group']);
    self::assertIsInt($auth['identity']['access_rank']);
  }

  public function testRegenerationFailureLeavesNoPartialLogin():void {
    $session = $this->session();
    $before = $_SESSION;
    $this->runtime->regenerationSucceeds = false;

    self::assertFalse($session->login($this->user()));
    self::assertFalse($session->isLoggedIn());
    self::assertNull($session->user());
    self::assertSame($before, $_SESSION);
    self::assertTrue($session->hasErrors());
  }

  public function testIdentityAndAccessRestoreOnNextRequest():void {
    $session = $this->session();
    self::assertTrue($session->login($this->user([
      'access_group' => AccessGroup::ADMIN,
      'access_rank' => AccessRank::ADMIN,
    ])));

    $restored = new Session(config: $this->config);

    self::assertTrue($restored->isLoggedIn());
    self::assertSame(42, $restored->id());
    self::assertSame('01234567890', $restored->name);
    self::assertSame(AccessGroup::ADMIN, $restored->access_group());
    self::assertSame(AccessRank::ADMIN->value, $restored->access_rank());
    self::assertSame('NG', ((array)$restored->user())['country_code']);
  }

  public function testGroupAndRankMustAgree():void {
    $session = $this->session();

    self::assertFalse($session->login($this->user([
      'access_group' => AccessGroup::USER,
      'access_rank' => AccessRank::OWNER,
    ])));
    self::assertSame(AccessGroup::GUEST, $session->access_group());
  }

  public function testRankOnlyLegacyProjectionDerivesCanonicalGroup():void {
    $user = $this->user(['access_rank' => '6']);
    unset($user->access_group);
    $session = $this->session();

    self::assertTrue($session->login($user));
    self::assertSame(AccessGroup::ADMIN, $session->access_group());
    self::assertSame(AccessRank::ADMIN->value, $session->access_rank());
  }

  /**
   * A group that was supplied but does not normalize must never fall back to
   * the rank, or the rank alone would decide privilege.
   */
  public function testSuppliedButUnusableGroupCannotEscalateThroughRank():void {
    foreach (['TOTALLY_BOGUS', '', null, 6] as $group) {
      $_SESSION = [];
      $session = new Session(config: $this->config);

      self::assertFalse($session->login($this->user([
        'access_group' => $group,
        'access_rank' => AccessRank::OWNER,
      ])));
      self::assertFalse($session->isLoggedIn());
      self::assertSame(AccessGroup::GUEST, $session->access_group());
      self::assertSame(AccessRank::GUEST->value, $session->access_rank());
    }
  }

  public function testSuppliedButUnusableRankIsRejectedRatherThanDerived():void {
    $session = $this->session();

    self::assertFalse($session->login($this->user([
      'access_group' => AccessGroup::ADMIN,
      'access_rank' => 'not-a-rank',
    ])));
    self::assertSame(AccessGroup::GUEST, $session->access_group());
  }

  public function testUnknownNegativeAndGuestPrivilegeFailClosed():void {
    foreach ([-1, 9, 999, AccessRank::GUEST] as $invalid) {
      $_SESSION = [];
      $session = new Session(config: $this->config);
      $user = $this->user(['access_rank' => $invalid]);
      unset($user->access_group);
      self::assertFalse($session->login($user));
      self::assertSame(AccessGroup::GUEST, $session->access_group());
    }
  }

  public function testTamperedRankCannotRestoreAuthentication():void {
    $session = $this->session();
    self::assertTrue($session->login($this->user()));
    $rotations = $this->runtime->regenerationCount;
    $root = $this->storedRoot();
    $auth = $this->storedAuth();
    $auth['access_rank'] = 999;
    $root['auth'] = $auth;
    $_SESSION['_timefrontiers_session'] = $root;

    $restored = new Session(config: $this->config);

    self::assertFalse($restored->isLoggedIn());
    self::assertSame(AccessRank::GUEST->value, $restored->access_rank());
    self::assertGreaterThan($rotations, $this->runtime->regenerationCount);
    self::assertTrue($restored->hasErrors());
  }

  public function testUnknownPayloadVersionIsRejected():void {
    $session = $this->session();
    self::assertTrue($session->login($this->user()));
    $root = $this->storedRoot();
    $auth = $this->storedAuth();
    $auth['version'] = 2;
    $root['auth'] = $auth;
    $_SESSION['_timefrontiers_session'] = $root;

    $restored = new Session(config: $this->config);

    self::assertFalse($restored->isLoggedIn());
  }

  public function testExpiryEqualityIsExpiredAndCannotBeExtended():void {
    $session = $this->session();
    self::assertTrue($session->login($this->user(), 60));
    $this->runtime->timestamp = $session->getExpiry();

    $restored = new Session(config: $this->config);

    self::assertFalse($restored->isLoggedIn());
    self::assertFalse($restored->extendExpiry(60));
  }

  public function testExtensionRequiresAuthenticationAndHonorsAbsoluteCap():void {
    $guest = $this->session();
    self::assertFalse($guest->extendExpiry(60));

    $config = new \TimeFrontiers\SessionConfig(
      defaultIdleLifetime: 100,
      maxIdleLifetime: 200,
      absoluteLifetime: 250,
      maxExpiryExtension: 200,
      runtime: $this->runtime
    );
    $session = new Session(config: $config);
    self::assertTrue($session->login($this->user(), 100));
    $this->runtime->timestamp += 80;

    self::assertTrue($session->extendExpiry(500));
    self::assertSame(1_800_000_250, $session->getExpiry());
  }

  public function testLogoutUsesMatchingCookieAttributesAndReportsFailures():void {
    $session = $this->session();
    self::assertTrue($session->login($this->user()));
    $this->runtime->destructionSucceeds = false;

    self::assertFalse($session->logout());
    self::assertFalse($session->isLoggedIn());
    self::assertNull($session->user());
    self::assertSame([], $_SESSION);
    self::assertSame('/', $this->runtime->cookies[0]['options']['path']);
    self::assertTrue($this->runtime->cookies[0]['options']['secure']);
    self::assertSame('Lax', $this->runtime->cookies[0]['options']['samesite']);
    self::assertTrue($session->hasErrors());
  }

  public function testCookieDeletionFailureStillResetsLocalState():void {
    $session = $this->session();
    self::assertTrue($session->login($this->user()));
    $this->runtime->cookieSucceeds = false;

    self::assertFalse($session->logout());
    self::assertFalse($session->isLoggedIn());
    self::assertSame([], $_SESSION);
  }

  public function testPersistentCookieIsUpdatedAtomicallyOnExtension():void {
    $config = new \TimeFrontiers\SessionConfig(
      cookieLifetime: 3600,
      runtime: $this->runtime
    );
    $session = $this->session($config);
    self::assertTrue($session->login($this->user(), 100));
    $originalExpiry = $session->getExpiry();
    $this->runtime->timestamp += 50;

    self::assertTrue($session->extendExpiry(200));
    self::assertGreaterThan($originalExpiry, $session->getExpiry());
    self::assertSame(
      $session->getExpiry(),
      $this->runtime->cookies[0]['options']['expires']
    );
  }

  public function testPersistentCookieFailureDoesNotCommitExtension():void {
    $config = new \TimeFrontiers\SessionConfig(
      cookieLifetime: 3600,
      runtime: $this->runtime
    );
    $session = $this->session($config);
    self::assertTrue($session->login($this->user(), 100));
    $originalExpiry = $session->getExpiry();
    $this->runtime->timestamp += 50;
    $this->runtime->cookieSucceeds = false;

    self::assertFalse($session->extendExpiry(200));
    self::assertSame($originalExpiry, $session->getExpiry());
  }
}
