<?php

declare(strict_types=1);

namespace TimeFrontiers\Tests;

use PHPUnit\Framework\TestCase;
use TimeFrontiers\AccessGroup;
use TimeFrontiers\AccessRank;
use TimeFrontiers\Session;

class SessionTest extends TestCase {

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  protected function setUp():void {
    // Use a writable path for session files.
    // In CLI mode PHP never sends actual HTTP headers, so we leave
    // session.use_cookies at its default (enabled) — disabling it causes
    // _configureSessionCookie() to emit a warning.
    ini_set('session.save_path', sys_get_temp_dir());

    // Tear down any leftover session from a previous test
    if (session_status() === PHP_SESSION_ACTIVE) {
      session_unset();
      session_destroy();
    }

    // Give each test its own session ID so tests don't bleed into each other.
    // PHP only allows [A-Za-z0-9,-] in session IDs — no underscores.
    session_id('tftest' . bin2hex(random_bytes(8)));

    // Clear any static errors left over from previous tests
    Session::clearErrors();
  }

  protected function tearDown():void {
    if (session_status() === PHP_SESSION_ACTIVE) {
      session_unset();
      session_destroy();
    }
    Session::clearErrors();
  }

  /**
   * Builds a minimal valid user object.
   *
   * @param array<string, mixed> $overrides
   */
  private function makeUser(array $overrides = []):object {
    return (object) array_merge([
      'id'           => 1,
      'uniqueid'     => '01234567890',
      'name'         => 'John',
      'surname'      => 'Doe',
      'access_group' => AccessGroup::USER,
      'access_rank'  => AccessRank::USER,
    ], $overrides);
  }

  /**
   * Simulates the end of a page request and the start of the next one
   * using the same session ID (i.e. the same browser cookie).
   *
   * Returns a freshly constructed Session as if the page was just loaded.
   */
  private function newRequest(string $session_id):Session {
    session_write_close();
    session_id($session_id);
    return new Session();
  }

  // ---------------------------------------------------------------------------
  // 1. Guest / constructor defaults
  // ---------------------------------------------------------------------------

  public function testNewSessionIsNotLoggedIn():void {
    $session = new Session();

    $this->assertFalse($session->isLoggedIn());
    $this->assertNull($session->id());
    $this->assertNull($session->user());
  }

  public function testGuestHasGuestGroupAndRank():void {
    $session = new Session();

    $this->assertSame(AccessGroup::GUEST, $session->access_group());
    $this->assertSame(AccessRank::GUEST->value, $session->access_rank());
  }

  public function testGuestNameHasGuestPrefix():void {
    $session = new Session();

    $this->assertStringStartsWith('GUEST_', $session->name);
  }

  // ---------------------------------------------------------------------------
  // 2. login()
  // ---------------------------------------------------------------------------

  public function testLoginReturnsTrueOnValidUser():void {
    $session = new Session();

    $this->assertTrue($session->login($this->makeUser()));
  }

  public function testLoginSetsLoggedIn():void {
    $session = new Session();
    $session->login($this->makeUser());

    $this->assertTrue($session->isLoggedIn());
  }

  public function testLoginSetsNameToUniqueid():void {
    $session = new Session();
    $session->login($this->makeUser(['uniqueid' => '09876543210']));

    $this->assertSame('09876543210', $session->name);
  }

  public function testLoginSetsUserId():void {
    $session = new Session();
    $session->login($this->makeUser(['id' => 42]));

    $this->assertSame(42, $session->id());
  }

  public function testLoginSetsUserObject():void {
    $session = new Session();
    $user    = $this->makeUser(['name' => 'Jane', 'surname' => 'Smith']);
    $session->login($user);

    $stored = $session->user();
    $this->assertNotNull($stored);
    $this->assertSame('Jane', $stored->name);
    $this->assertSame('Smith', $stored->surname);
  }

  public function testLoginSetsAccessGroupFromUser():void {
    $session = new Session();
    $session->login($this->makeUser(['access_group' => AccessGroup::MODERATOR]));

    $this->assertSame(AccessGroup::MODERATOR, $session->access_group());
  }

  public function testLoginSetsAccessRankFromUser():void {
    $session = new Session();
    $session->login($this->makeUser(['access_rank' => AccessRank::ADMIN]));

    $this->assertSame(AccessRank::ADMIN->value, $session->access_rank());
  }

  public function testLoginSetsExpiryInFuture():void {
    $session = new Session();
    $session->login($this->makeUser());

    $this->assertGreaterThan(time(), $session->getExpiry());
  }

  public function testLoginReturnsFalseWhenIdMissing():void {
    $session = new Session();
    $user    = (object)['uniqueid' => '01234567890'];

    $this->assertFalse($session->login($user));
    $this->assertTrue($session->hasErrors());
  }

  public function testLoginReturnsFalseWhenUniqueidMissing():void {
    $session = new Session();
    $user    = (object)['id' => 1];

    $this->assertFalse($session->login($user));
    $this->assertTrue($session->hasErrors());
  }

  public function testLoginReturnsFalseWhenUniqueidIsNull():void {
    $session = new Session();
    $user    = (object)['id' => 1, 'uniqueid' => null];

    $this->assertFalse($session->login($user));
  }

  // ---------------------------------------------------------------------------
  // 3. session_lifetime edge cases (the zero-lifetime bug)
  // ---------------------------------------------------------------------------

  public function testZeroLifetimeFallsBackToDefault():void {
    $session = new Session();
    $session->login($this->makeUser(), 0);

    // Should be well in the future, not expired
    $this->assertGreaterThan(time() + 60, $session->getExpiry());
  }

  public function testNegativeLifetimeFallsBackToDefault():void {
    $session = new Session();
    $session->login($this->makeUser(), -500);

    $this->assertGreaterThan(time() + 60, $session->getExpiry());
  }

  public function testCustomPositiveLifetimeIsRespected():void {
    $session = new Session();
    $session->login($this->makeUser(), 7200);

    // Expiry should be ~7200s from now (allow a couple seconds tolerance)
    $this->assertGreaterThan(time() + 7000, $session->getExpiry());
    $this->assertLessThan(time() + 7300, $session->getExpiry());
  }

  // ---------------------------------------------------------------------------
  // 4. Session persistence across page requests
  // ---------------------------------------------------------------------------

  public function testLoginPersistsToNextRequest():void {
    $session   = new Session();
    $session->login($this->makeUser());
    $sessionId = session_id();

    $session2 = $this->newRequest($sessionId);

    $this->assertTrue($session2->isLoggedIn());
  }

  public function testNamePersistsToNextRequest():void {
    $session = new Session();
    $session->login($this->makeUser(['uniqueid' => '11111111111']));
    $sessionId = session_id();

    $session2 = $this->newRequest($sessionId);

    $this->assertSame('11111111111', $session2->name);
  }

  public function testUserIdPersistsToNextRequest():void {
    $session = new Session();
    $session->login($this->makeUser(['id' => 99]));
    $sessionId = session_id();

    $session2 = $this->newRequest($sessionId);

    $this->assertSame(99, $session2->id());
  }

  public function testAccessGroupPersistsToNextRequest():void {
    $session = new Session();
    $session->login($this->makeUser(['access_group' => AccessGroup::ADMIN]));
    $sessionId = session_id();

    $session2 = $this->newRequest($sessionId);

    $this->assertSame(AccessGroup::ADMIN, $session2->access_group());
  }

  public function testAccessRankPersistsToNextRequest():void {
    $session = new Session();
    $session->login($this->makeUser(['access_rank' => AccessRank::ADMIN]));
    $sessionId = session_id();

    $session2 = $this->newRequest($sessionId);

    $this->assertSame(AccessRank::ADMIN->value, $session2->access_rank());
  }

  public function testExpiredSessionIsNotRestoredOnNextRequest():void {
    $session = new Session();
    // Login with 1-second lifetime — will have expired by the next request
    $session->login($this->makeUser(), 1);
    $sessionId = session_id();

    // Wait for it to expire
    sleep(2);

    $session2 = $this->newRequest($sessionId);

    $this->assertFalse($session2->isLoggedIn());
  }

  // ---------------------------------------------------------------------------
  // 5. logout()
  // ---------------------------------------------------------------------------

  public function testLogoutClearsLoggedIn():void {
    $session = new Session();
    $session->login($this->makeUser());
    $session->logout();

    $this->assertFalse($session->isLoggedIn());
  }

  public function testLogoutClearsUser():void {
    $session = new Session();
    $session->login($this->makeUser());
    $session->logout();

    $this->assertNull($session->user());
    $this->assertNull($session->id());
  }

  public function testLogoutResetsToGuestGroup():void {
    $session = new Session();
    $session->login($this->makeUser(['access_group' => AccessGroup::ADMIN]));
    $session->logout();

    $this->assertSame(AccessGroup::GUEST, $session->access_group());
    $this->assertSame(AccessRank::GUEST->value, $session->access_rank());
  }

  public function testLogoutReturnTrue():void {
    $session = new Session();
    $session->login($this->makeUser());

    $this->assertTrue($session->logout());
  }

  // ---------------------------------------------------------------------------
  // 6. Expiry helpers
  // ---------------------------------------------------------------------------

  public function testIsExpiredReturnsFalseForActiveSession():void {
    $session = new Session();
    $session->login($this->makeUser());

    $this->assertFalse($session->isExpired());
  }

  public function testIsExpiredReturnsFalseForGuest():void {
    $session = new Session(); // not logged in, _expire = 0

    $this->assertFalse($session->isExpired());
  }

  public function testExtendExpiryIncreasesExpiry():void {
    $session = new Session();
    $session->login($this->makeUser(), 1800);
    $before = $session->getExpiry();

    $session->extendExpiry(3600);

    $this->assertGreaterThan($before, $session->getExpiry());
  }

  public function testExtendExpiryReturnsFalseForZero():void {
    $session = new Session();
    $session->login($this->makeUser());

    $this->assertFalse($session->extendExpiry(0));
  }

  public function testExtendExpiryReturnsFalseForNegative():void {
    $session = new Session();
    $session->login($this->makeUser());

    $this->assertFalse($session->extendExpiry(-100));
  }

  // ---------------------------------------------------------------------------
  // 7. CSRF tokens
  // ---------------------------------------------------------------------------

  public function testGenerateCSRFTokenReturnsNonEmptyString():void {
    $session = new Session();
    $token   = $session->generateCSRFToken('test_form');

    $this->assertNotEmpty($token);
    $this->assertIsString($token);
  }

  public function testValidCSRFTokenIsAccepted():void {
    $session = new Session();
    $token   = $session->generateCSRFToken('test_form');

    $this->assertTrue($session->validateCSRFToken('test_form', $token));
  }

  public function testWrongCSRFTokenIsRejected():void {
    $session = new Session();
    $session->generateCSRFToken('test_form');

    $this->assertFalse($session->validateCSRFToken('test_form', 'wrong_token'));
  }

  public function testCSRFTokenIsSingleUse():void {
    $session = new Session();
    $token   = $session->generateCSRFToken('test_form');

    $session->validateCSRFToken('test_form', $token); // consume it
    $this->assertFalse($session->validateCSRFToken('test_form', $token));
  }

  public function testCSRFTokenForUnknownFormIsRejected():void {
    $session = new Session();

    $this->assertFalse($session->validateCSRFToken('no_such_form', 'anything'));
  }

  public function testCSRFTokenExpiredIsRejected():void {
    $session = new Session();
    $token   = $session->generateCSRFToken('test_form', 1); // 1-second lifetime

    sleep(2);

    $this->assertFalse($session->validateCSRFToken('test_form', $token));
  }

  public function testCsrfFieldReturnsHiddenInput():void {
    $session = new Session();
    $html    = $session->csrfField('test_form');

    $this->assertStringContainsString('<input', $html);
    $this->assertStringContainsString('type="hidden"', $html);
    $this->assertStringContainsString('name="_csrf_token"', $html);
  }

  public function testDifferentFormsGetDifferentTokens():void {
    $session = new Session();
    $t1      = $session->generateCSRFToken('form_a');
    $t2      = $session->generateCSRFToken('form_b');

    $this->assertNotSame($t1, $t2);
  }

  // ---------------------------------------------------------------------------
  // 8. Flash messages
  // ---------------------------------------------------------------------------

  public function testFlashIsStoredAndRetrieved():void {
    $session = new Session();
    $session->flash('success', 'Saved!');

    $this->assertTrue($session->hasFlash('success'));
    $this->assertSame('Saved!', $session->getFlash('success'));
  }

  public function testFlashIsRemovedAfterRetrieval():void {
    $session = new Session();
    $session->flash('info', 'Hello');
    $session->getFlash('info'); // consume

    $this->assertFalse($session->hasFlash('info'));
  }

  public function testGetFlashReturnsDefaultWhenMissing():void {
    $session = new Session();

    $this->assertNull($session->getFlash('missing'));
    $this->assertSame('fallback', $session->getFlash('missing', 'fallback'));
  }

  // ---------------------------------------------------------------------------
  // 9. User object storage (set / get / has / remove / all)
  // ---------------------------------------------------------------------------

  public function testSetAndGetOnUserObject():void {
    $session = new Session();
    $session->login($this->makeUser());
    $session->set('theme', 'dark');

    $this->assertSame('dark', $session->get('theme'));
  }

  public function testHasReturnsTrueForExistingKey():void {
    $session = new Session();
    $session->login($this->makeUser());
    $session->set('pref', 'value');

    $this->assertTrue($session->has('pref'));
  }

  public function testHasReturnsFalseForMissingKey():void {
    $session = new Session();
    $session->login($this->makeUser());

    $this->assertFalse($session->has('nonexistent'));
  }

  public function testRemoveDeletesKey():void {
    $session = new Session();
    $session->login($this->makeUser());
    $session->set('temp', 'gone');
    $session->remove('temp');

    $this->assertFalse($session->has('temp'));
  }

  public function testGetReturnsDefaultForMissingKey():void {
    $session = new Session();
    $session->login($this->makeUser());

    $this->assertSame('default_val', $session->get('missing', 'default_val'));
  }

  public function testAllReturnsUserProperties():void {
    $session = new Session();
    $session->login($this->makeUser(['name' => 'Ali']));

    $all = $session->all();
    $this->assertIsArray($all);
    $this->assertArrayHasKey('name', $all);
    $this->assertSame('Ali', $all['name']);
  }

  public function testAllReturnsEmptyArrayWhenNotLoggedIn():void {
    $session = new Session();

    $this->assertSame([], $session->all());
  }

  // ---------------------------------------------------------------------------
  // 10. Access control
  // ---------------------------------------------------------------------------

  public function testHasRankReturnsTrueWhenRankSufficient():void {
    $session = new Session();
    $session->login($this->makeUser(['access_rank' => AccessRank::ADMIN]));

    $this->assertTrue($session->hasRank(AccessRank::MODERATOR));
    $this->assertTrue($session->hasRank(AccessRank::ADMIN));
  }

  public function testHasRankReturnsFalseWhenRankInsufficient():void {
    $session = new Session();
    $session->login($this->makeUser(['access_rank' => AccessRank::USER]));

    $this->assertFalse($session->hasRank(AccessRank::MODERATOR));
  }

  public function testHasRankAcceptsIntegerArgument():void {
    $session = new Session();
    $session->login($this->makeUser(['access_rank' => AccessRank::ADMIN]));

    $this->assertTrue($session->hasRank(AccessRank::ADMIN->value));
    $this->assertFalse($session->hasRank(AccessRank::OWNER->value));
  }

  public function testInGroupReturnsTrueForMatchingGroup():void {
    $session = new Session();
    $session->login($this->makeUser(['access_group' => AccessGroup::MODERATOR]));

    $this->assertTrue($session->inGroup(AccessGroup::MODERATOR));
  }

  public function testInGroupReturnsFalseForDifferentGroup():void {
    $session = new Session();
    $session->login($this->makeUser(['access_group' => AccessGroup::USER]));

    $this->assertFalse($session->inGroup(AccessGroup::MODERATOR));
  }

  public function testInGroupAcceptsStringArgument():void {
    $session = new Session();
    $session->login($this->makeUser(['access_group' => AccessGroup::ADMIN]));

    $this->assertTrue($session->inGroup('ADMIN'));
    $this->assertFalse($session->inGroup('GUEST'));
  }

  public function testIsStaffTrueForModeratorAndAbove():void {
    $session = new Session();
    $session->login($this->makeUser(['access_rank' => AccessRank::MODERATOR]));

    $this->assertTrue($session->isStaff());
  }

  public function testIsStaffFalseBelowModerator():void {
    $session = new Session();
    $session->login($this->makeUser(['access_rank' => AccessRank::USER]));

    $this->assertFalse($session->isStaff());
  }

  public function testIsTechnicalTrueForDeveloperAndAbove():void {
    $session = new Session();
    $session->login($this->makeUser(['access_rank' => AccessRank::DEVELOPER]));

    $this->assertTrue($session->isTechnical());
  }

  public function testIsTechnicalFalseForAdmin():void {
    // ADMIN (6) is below DEVELOPER (7)
    $session = new Session();
    $session->login($this->makeUser(['access_rank' => AccessRank::ADMIN]));

    $this->assertFalse($session->isTechnical());
  }

  public function testIsAdminTrueForAdminAndAbove():void {
    $session = new Session();
    $session->login($this->makeUser(['access_rank' => AccessRank::ADMIN]));

    $this->assertTrue($session->isAdmin());
  }

  public function testIsAdminFalseForModerator():void {
    $session = new Session();
    $session->login($this->makeUser(['access_rank' => AccessRank::MODERATOR]));

    $this->assertFalse($session->isAdmin());
  }

  // ---------------------------------------------------------------------------
  // 11. User sanitization (_sanitizeUser — tested via session round-trip)
  // ---------------------------------------------------------------------------

  public function testEnumFieldsStoredAsScalarsInSession():void {
    $session = new Session();
    $session->login($this->makeUser([
      'access_group' => AccessGroup::MODERATOR,
      'access_rank'  => AccessRank::MODERATOR,
    ]));

    // The user stored in $_SESSION must not contain enum objects —
    // plain PHP can't deserialize them without the class loaded
    $stored = $_SESSION['user'] ?? null;
    $this->assertNotNull($stored);
    $this->assertIsString($stored->access_group);
    $this->assertNotInstanceOf(\UnitEnum::class, $stored->access_group);
  }

  public function testNestedObjectInUserIsSanitized():void {
    $meta       = new \stdClass();
    $meta->plan = 'pro';

    $session = new Session();
    $session->login($this->makeUser(['meta' => $meta]));

    $stored = $_SESSION['user'] ?? null;
    $this->assertNotNull($stored);
    $this->assertInstanceOf(\stdClass::class, $stored->meta);
    $this->assertSame('pro', $stored->meta->plan);
  }

  public function testNumericStringRankFromDatabaseIsNormalized():void {
    // Simulates a user object built directly from a database row where
    // access_rank arrives as a string (e.g. PDO::FETCH_OBJ with no type casting)
    $session = new Session();
    $session->login($this->makeUser(['access_rank' => '4'])); // '4' = MODERATOR

    $this->assertSame(AccessRank::MODERATOR->value, $session->access_rank());
  }

  public function testStringGroupFromDatabaseIsNormalized():void {
    $session = new Session();
    $session->login($this->makeUser(['access_group' => 'ADMIN']));

    $this->assertSame(AccessGroup::ADMIN, $session->access_group());
  }

  // ---------------------------------------------------------------------------
  // 12. Error handling
  // ---------------------------------------------------------------------------

  public function testHasErrorsFalseByDefault():void {
    $session = new Session();

    $this->assertFalse($session->hasErrors());
  }

  public function testHasErrorsTrueAfterFailedLogin():void {
    $session = new Session();
    $session->login((object)['uniqueid' => 'x']); // no id

    $this->assertTrue($session->hasErrors());
  }

  public function testGetErrorsReturnsArray():void {
    $session = new Session();
    $session->login((object)['uniqueid' => 'x']); // triggers error

    $errors = $session->getErrors();
    $this->assertIsArray($errors);
    $this->assertArrayHasKey('login', $errors);
  }

  public function testClearErrorsEmptiesCollection():void {
    $session = new Session();
    $session->login((object)['uniqueid' => 'x']);
    Session::clearErrors();

    $this->assertFalse($session->hasErrors());
  }

  // ---------------------------------------------------------------------------
  // 13. Backward-compat shims
  // ---------------------------------------------------------------------------

  public function testCreateCSRFtokenAndIsValidCSRFtoken():void {
    $session = new Session();
    $token   = $session->createCSRFtoken('legacy_form');

    $this->assertNotEmpty($token);
    $this->assertTrue($session->isValidCSRFtoken('legacy_form', $token));
  }

  public function testLoggedInAliasMatchesIsLoggedIn():void {
    $session = new Session();
    $this->assertSame($session->isLoggedIn(), $session->loggedIn());

    $session->login($this->makeUser());
    $this->assertSame($session->isLoggedIn(), $session->loggedIn());
  }

  public function testGetUserIdAliasMatchesId():void {
    $session = new Session();
    $session->login($this->makeUser(['id' => 55]));

    $this->assertSame($session->id(), $session->getUserId());
  }
}
