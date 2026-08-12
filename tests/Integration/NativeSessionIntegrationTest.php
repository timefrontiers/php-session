<?php

declare(strict_types=1);

namespace TimeFrontiers\Tests\Integration;

use PHPUnit\Framework\Attributes\PreserveGlobalState;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use PHPUnit\Framework\TestCase;
use TimeFrontiers\Session;
use TimeFrontiers\SessionConfig;

#[RunTestsInSeparateProcesses]
#[PreserveGlobalState(false)]
final class NativeSessionIntegrationTest extends TestCase {

  private string $savePath;

  protected function setUp():void {
    parent::setUp();
    $this->savePath = \sys_get_temp_dir()
      . DIRECTORY_SEPARATOR
      . 'timefrontiers-session-test-'
      . \bin2hex(\random_bytes(8));
    self::assertTrue(\mkdir($this->savePath, 0700));
    self::assertNotFalse(\ini_set('session.save_path', $this->savePath));
    $_SESSION = [];
  }

  protected function tearDown():void {
    if (\session_status() === PHP_SESSION_ACTIVE) {
      \session_write_close();
    }
    \session_id('');
    if (isset($this->savePath) && \is_dir($this->savePath)) {
      foreach (new \FilesystemIterator($this->savePath) as $file) {
        if (
          $file instanceof \SplFileInfo
          && $file->isFile()
          && \str_starts_with($file->getFilename(), 'sess_')
        ) {
          \unlink($file->getPathname());
        }
      }
      \rmdir($this->savePath);
    }
    parent::tearDown();
  }

  public function testOldGuestIdCannotRestoreAuthentication():void {
    $config = new SessionConfig(cookieName: 'TFNATIVESESSID');
    $session = new Session(config: $config);
    $guestId = \session_id();
    self::assertIsString($guestId);
    self::assertTrue($session->login((object)[
      'id' => 42,
      'uniqueid' => '01234567890',
    ]));
    $authenticatedId = \session_id();
    self::assertIsString($authenticatedId);
    self::assertNotSame($guestId, $authenticatedId);
    self::assertTrue(\session_write_close());

    \session_id($guestId);
    $oldSession = new Session(config: $config);
    self::assertFalse($oldSession->isLoggedIn());
    self::assertNotSame($guestId, \session_id());
    self::assertTrue(\session_write_close());

    \session_id($authenticatedId);
    $restored = new Session(config: $config);
    self::assertTrue($restored->isLoggedIn());
    self::assertSame(42, $restored->id());
  }

  public function testLogoutDestroysAuthenticatedHandlerState():void {
    $config = new SessionConfig(cookieName: 'TFNATIVESESSID');
    $session = new Session(config: $config);
    self::assertTrue($session->login((object)[
      'id' => 42,
      'uniqueid' => '01234567890',
    ]));
    $authenticatedId = \session_id();
    self::assertIsString($authenticatedId);

    self::assertTrue($session->logout());
    self::assertFalse($session->isLoggedIn());
    self::assertFileDoesNotExist($this->savePath . DIRECTORY_SEPARATOR . 'sess_' . $authenticatedId);
  }
}
