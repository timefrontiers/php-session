<?php

declare(strict_types=1);

namespace TimeFrontiers\Tests;

use PHPUnit\Framework\TestCase;
use TimeFrontiers\Session;
use TimeFrontiers\AccessRank;

class SessionCsrfTest extends TestCase
{
  private Session $session;

  protected function setUp(): void
  {
    parent::setUp();
    
    if (session_status() === PHP_SESSION_ACTIVE) {
      session_destroy();
    }
    $_SESSION = [];
    
    $this->session = new Session();
  }

  protected function tearDown(): void
  {
    if (session_status() === PHP_SESSION_ACTIVE) {
      session_destroy();
    }
    $_SESSION = [];
    
    parent::tearDown();
  }

  /** @test */
  public function generateCSRFToken_creates_unique_token(): void
  {
    $token1 = $this->session->generateCSRFToken('form1');
    $token2 = $this->session->generateCSRFToken('form1');
    
    $this->assertIsString($token1);
    $this->assertSame(64, strlen($token1)); // 32 bytes = 64 hex chars
    $this->assertNotSame($token1, $token2);
  }

  /** @test */
  public function generateCSRFToken_stores_token_in_session_with_expiry(): void
  {
    $formId = 'test_form';
    $expirySeconds = 60;
    
    $token = $this->session->generateCSRFToken($formId, $expirySeconds);
    
    $this->assertArrayHasKey('csrf_tokens', $_SESSION);
    $this->assertArrayHasKey($formId, $_SESSION['csrf_tokens']);
    
    $stored = $_SESSION['csrf_tokens'][$formId];
    $this->assertSame($token, $stored['token']);
    $this->assertEqualsWithDelta(time() + $expirySeconds, $stored['expire'], 2);
  }

  /** @test */
  public function validateCSRFToken_returns_true_for_valid_token(): void
  {
    $formId = 'test_form';
    $token = $this->session->generateCSRFToken($formId);
    
    $result = $this->session->validateCSRFToken($formId, $token);
    
    $this->assertTrue($result);
  }

  /** @test */
  public function validateCSRFToken_returns_false_for_invalid_token(): void
  {
    $formId = 'test_form';
    $this->session->generateCSRFToken($formId);
    
    $result = $this->session->validateCSRFToken($formId, 'invalid_token');
    
    $this->assertFalse($result);
  }

  /** @test */
  public function validateCSRFToken_returns_false_for_unknown_form(): void
  {
    $result = $this->session->validateCSRFToken('unknown_form', 'some_token');
    
    $this->assertFalse($result);
  }

  /** @test */
  public function validateCSRFToken_returns_false_for_expired_token(): void
  {
    $formId = 'test_form';
    $token = $this->session->generateCSRFToken($formId, -1); // Expired immediately
    
    // Simulate time passing by modifying session directly
    $_SESSION['csrf_tokens'][$formId]['expire'] = time() - 1;
    
    $result = $this->session->validateCSRFToken($formId, $token);
    
    $this->assertFalse($result);
  }

  /** @test */
  public function validateCSRFToken_removes_token_after_validation(): void
  {
    $formId = 'test_form';
    $token = $this->session->generateCSRFToken($formId);
    
    $this->session->validateCSRFToken($formId, $token);
    
    $this->assertArrayNotHasKey($formId, $_SESSION['csrf_tokens']);
  }

  /** @test */
  public function validateCSRFToken_removes_token_even_on_failure(): void
  {
    $formId = 'test_form';
    $this->session->generateCSRFToken($formId);
    
    $this->session->validateCSRFToken($formId, 'wrong_token');
    
    $this->assertArrayNotHasKey($formId, $_SESSION['csrf_tokens']);
  }

  /** @test */
  public function backward_compatibility_createCSRFtoken_works(): void
  {
    $form = 'legacy_form';
    $expiry = time() + 3600;
    
    $token = $this->session->createCSRFtoken($form, $expiry);
    
    $this->assertIsString($token);
    $this->assertSame(64, strlen($token));
    $this->assertArrayHasKey($form, $_SESSION['csrf_tokens']);
  }

  /** @test */
  public function backward_compatibility_isValidCSRFtoken_works(): void
  {
    $form = 'legacy_form';
    $token = $this->session->createCSRFtoken($form);
    
    $result = $this->session->isValidCSRFtoken($form, $token);
    
    $this->assertTrue($result);
  }
}