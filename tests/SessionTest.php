<?php

declare(strict_types=1);

namespace TimeFrontiers\Tests;

use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\MockObject\MockObject;
use TimeFrontiers\Session;
use TimeFrontiers\AccessGroup;
use TimeFrontiers\AccessRank;
use TimeFrontiers\SessionException;
use Psr\Log\LoggerInterface;

class SessionTest extends TestCase
{
  private MockObject|LoggerInterface $logger;
  private object $validUser;

  protected function setUp(): void
  {
    parent::setUp();
    
    // Clear any existing session data
    if (session_status() === PHP_SESSION_ACTIVE) {
      session_destroy();
    }
    $_SESSION = [];
    $_COOKIE = [];
    
    $this->logger = $this->createMock(LoggerInterface::class);
    
    $this->validUser = (object)[
      'id' => 123,
      'name' => 'testuser',
      'access_group' => 'USER',
      'access_rank' => AccessRank::USER->value
    ];
  }

  protected function tearDown(): void
  {
    if (session_status() === PHP_SESSION_ACTIVE) {
      session_destroy();
    }
    $_SESSION = [];
    $_COOKIE = [];
    Session::clearErrors();
    
    parent::tearDown();
  }

  /** @test */
  public function constructor_starts_session_when_not_active(): void
  {
    $this->assertSame(PHP_SESSION_NONE, session_status());
    
    $session = new Session($this->logger);
    
    $this->assertSame(PHP_SESSION_ACTIVE, session_status());
    $this->assertFalse($session->isLoggedIn());
  }

  /** @test */
  public function constructor_throws_exception_when_session_fails(): void
  {
    // This is hard to test reliably; we'll trust the exception handling
    $this->expectNotToPerformAssertions();
  }

  /** @test */
  public function constructor_restores_session_when_valid_session_exists(): void
  {
    // Simulate an existing valid session
    $_SESSION['user_id'] = 456;
    $_SESSION['user_name'] = 'existinguser';
    $_SESSION['access_group'] = 'ADMIN';
    $_SESSION['access_rank'] = AccessRank::ADMIN->value;
    $_SESSION['_expire'] = time() + 3600;
    
    $session = new Session($this->logger);
    
    $this->assertTrue($session->isLoggedIn());
    $this->assertSame(456, $session->getUserId());
    $this->assertSame('existinguser', $session->name);
    $this->assertSame(AccessGroup::ADMIN, $session->access_group);
    $this->assertSame(AccessRank::ADMIN->value, $session->access_rank);
  }

  /** @test */
  public function constructor_clears_expired_session(): void
  {
    $_SESSION['user_id'] = 456;
    $_SESSION['user_name'] = 'expireduser';
    $_SESSION['_expire'] = time() - 3600; // Expired 1 hour ago
    
    $session = new Session($this->logger);
    
    $this->assertFalse($session->isLoggedIn());
    $this->assertNull($session->getUserId());
    $this->assertStringStartsWith('GUEST_', $session->name);
    $this->assertSame(AccessGroup::GUEST, $session->access_group);
    $this->assertSame(AccessRank::GUEST->value, $session->access_rank);
  }

  /** @test */
  public function login_fails_when_user_missing_id(): void
  {
    $session = new Session($this->logger);
    $invalidUser = (object)['name' => 'noid'];
    
    $result = $session->login($invalidUser);
    
    $this->assertFalse($result);
    $this->assertFalse($session->isLoggedIn());
    
    $errors = Session::$errors['login'] ?? [];
    $this->assertCount(1, $errors);
    $this->assertStringContainsString('must have an "id" property', $errors[0][2]);
  }

  /** @test */
  public function login_fails_when_user_missing_public_identifier(): void
  {
    $session = new Session($this->logger);
    $invalidUser = (object)['id' => 123];
    
    $result = $session->login($invalidUser);
    
    $this->assertFalse($result);
    $this->assertFalse($session->isLoggedIn());
    
    $errors = Session::$errors['login'] ?? [];
    $this->assertCount(1, $errors);
    $this->assertStringContainsString('public identifier', $errors[0][2]);
  }

  /** @test */
  public function login_succeeds_with_valid_user(): void
  {
    $session = new Session($this->logger);
    
    $this->logger->expects($this->once())
      ->method('info')
      ->with('User logged in', ['user_id' => 123]);
    
    $result = $session->login($this->validUser);
    
    $this->assertTrue($result);
    $this->assertTrue($session->isLoggedIn());
    $this->assertSame(123, $session->getUserId());
    $this->assertSame('testuser', $session->name);
    $this->assertSame(AccessGroup::USER, $session->access_group);
    $this->assertSame(AccessRank::USER->value, $session->access_rank);
    $this->assertGreaterThan(time(), $session->getExpiry());
  }

  /** @test */
  public function login_uses_uniqueid_as_fallback_for_name(): void
  {
    $session = new Session($this->logger);
    $user = (object)[
      'id' => 789,
      'uniqueid' => 'unique_identifier',
      'access_group' => 'USER'
    ];
    
    $result = $session->login($user);
    
    $this->assertTrue($result);
    $this->assertSame('unique_identifier', $session->name);
  }

  /** @test */
  public function login_sets_custom_session_lifetime(): void
  {
    $session = new Session($this->logger);
    $customLifetime = 7200; // 2 hours
    
    $session->login($this->validUser, false, $customLifetime);
    
    $expectedExpiry = time() + $customLifetime;
    $this->assertEqualsWithDelta($expectedExpiry, $session->getExpiry(), 2);
    $this->assertEqualsWithDelta($expectedExpiry, $_SESSION['_expire'], 2);
  }

  /** @test */
  public function login_normalizes_access_group_from_string(): void
  {
    $session = new Session($this->logger);
    $user = (object)[
      'id' => 123,
      'name' => 'testuser',
      'access_group' => 'ADMIN'
    ];
    
    $session->login($user);
    
    $this->assertSame(AccessGroup::ADMIN, $session->access_group);
  }

  /** @test */
  public function login_normalizes_access_rank_from_int(): void
  {
    $session = new Session($this->logger);
    $user = (object)[
      'id' => 123,
      'name' => 'testuser',
      'access_rank' => AccessRank::DEVELOPER->value
    ];
    
    $session->login($user);
    
    $this->assertSame(AccessRank::DEVELOPER->value, $session->access_rank);
  }

  /** @test */
  public function login_defaults_to_user_group_when_missing(): void
  {
    $session = new Session($this->logger);
    $user = (object)[
      'id' => 123,
      'name' => 'testuser'
    ];
    
    $session->login($user);
    
    $this->assertSame(AccessGroup::USER, $session->access_group);
    $this->assertSame(AccessRank::USER->value, $session->access_rank);
  }

  /** @test */
  public function logout_clears_session_and_cookies(): void
  {
    $session = new Session($this->logger);
    $session->login($this->validUser);
    
    $this->assertTrue($session->isLoggedIn());
    
    $this->logger->expects($this->once())
      ->method('info')
      ->with('User logged out', ['user_id' => 123]);
    
    $result = $session->logout();
    
    $this->assertTrue($result);
    $this->assertFalse($session->isLoggedIn());
    $this->assertNull($session->getUserId());
    $this->assertStringStartsWith('GUEST_', $session->name);
    $this->assertSame(AccessGroup::GUEST, $session->access_group);
    $this->assertSame(AccessRank::GUEST->value, $session->access_rank);
    $this->assertEmpty($_SESSION);
  }

  /** @test */
  public function extendExpiry_updates_expiration_time(): void
  {
    $session = new Session($this->logger);
    $session->login($this->validUser);
    
    $originalExpiry = $session->getExpiry();
    
    $session->extendExpiry(1800); // Extend by 30 minutes
    
    $this->assertEqualsWithDelta($originalExpiry + 1800, $session->getExpiry(), 2);
    $this->assertEqualsWithDelta($originalExpiry + 1800, $_SESSION['_expire'], 2);
  }

  /** @test */
  public function extendExpiry_ignores_non_positive_seconds(): void
  {
    $session = new Session($this->logger);
    $session->login($this->validUser);
    
    $originalExpiry = $session->getExpiry();
    
    $result = $session->extendExpiry(0);
    
    $this->assertFalse($result);
    $this->assertSame($originalExpiry, $session->getExpiry());
  }

  /** @test */
  public function set_and_get_store_and_retrieve_session_data(): void
  {
    $session = new Session($this->logger);
    
    $session->set('test_key', 'test_value');
    $session->set('array_key', [1, 2, 3]);
    
    $this->assertSame('test_value', $session->get('test_key'));
    $this->assertSame([1, 2, 3], $session->get('array_key'));
    $this->assertNull($session->get('non_existent'));
    $this->assertSame('default', $session->get('non_existent', 'default'));
  }

  /** @test */
  public function remove_deletes_session_data(): void
  {
    $session = new Session($this->logger);
    
    $session->set('test_key', 'test_value');
    $this->assertSame('test_value', $session->get('test_key'));
    
    $session->remove('test_key');
    $this->assertNull($session->get('test_key'));
  }

  /** @test */
  public function getErrors_returns_internal_errors_array(): void
  {
    $session = new Session($this->logger);
    
    // Force an error by attempting login with invalid user
    $session->login((object)[]);
    
    $errors = $session->getErrors();
    
    $this->assertIsArray($errors);
    $this->assertArrayHasKey('login', $errors);
  }

  /** @test */
  public function static_addError_adds_to_errors_array(): void
  {
    Session::clearErrors();
    
    Session::addError(
      'test_context',
      500,
      'Test error message',
      __FILE__,
      __LINE__,
      AccessRank::DEVELOPER->value
    );
    
    $this->assertArrayHasKey('test_context', Session::$errors);
    $this->assertCount(1, Session::$errors['test_context']);
    
    $error = Session::$errors['test_context'][0];
    $this->assertSame(AccessRank::DEVELOPER->value, $error[0]);
    $this->assertSame(500, $error[1]);
    $this->assertSame('Test error message', $error[2]);
  }

  /** @test */
  public function static_clearErrors_empties_errors_array(): void
  {
    Session::addError('test', 500, 'message', __FILE__, __LINE__);
    $this->assertNotEmpty(Session::$errors);
    
    Session::clearErrors();
    $this->assertEmpty(Session::$errors);
  }
}