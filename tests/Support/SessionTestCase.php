<?php

declare(strict_types=1);

namespace TimeFrontiers\Tests\Support;

use PHPUnit\Framework\TestCase;
use TimeFrontiers\AccessGroup;
use TimeFrontiers\AccessRank;
use TimeFrontiers\Session;
use TimeFrontiers\SessionConfig;

abstract class SessionTestCase extends TestCase {

  protected FakeSessionRuntime $runtime;
  protected SessionConfig $config;

  protected function setUp():void {
    parent::setUp();
    Session::clearErrors();
    $_SESSION = [];
    $this->runtime = new FakeSessionRuntime();
    $this->config = new SessionConfig(runtime: $this->runtime);
  }

  protected function session(?SessionConfig $config = null):Session {
    return new Session(config: $config ?? $this->config);
  }

  /** @param array<string, mixed> $overrides */
  protected function user(array $overrides = []):object {
    return (object)\array_replace([
      'id' => 42,
      'uniqueid' => '01234567890',
      'name' => 'Ada',
      'surname' => 'Lovelace',
      'country_code' => 'ng',
      'avatar' => '/avatar/ada.png',
      'auth_version' => 3,
      'access_group' => AccessGroup::USER,
      'access_rank' => AccessRank::USER,
    ], $overrides);
  }

  /** @return array<string, mixed> */
  protected function storedRoot():array {
    $value = $_SESSION['_timefrontiers_session'] ?? [];
    if (!\is_array($value)) {
      return [];
    }
    $root = [];
    foreach ($value as $key => $item) {
      if (\is_string($key)) {
        $root[$key] = $item;
      }
    }
    return $root;
  }

  /** @return array<string, mixed> */
  protected function storedAuth():array {
    $value = $this->storedRoot()['auth'] ?? [];
    if (!\is_array($value)) {
      return [];
    }
    $auth = [];
    foreach ($value as $key => $item) {
      if (\is_string($key)) {
        $auth[$key] = $item;
      }
    }
    return $auth;
  }
}
