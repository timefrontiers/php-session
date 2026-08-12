<?php

declare(strict_types=1);

namespace TimeFrontiers\Tests\Support;

use TimeFrontiers\SessionRuntimeInterface;

final class FakeSessionRuntime implements SessionRuntimeInterface {

  public int $sessionStatus = PHP_SESSION_NONE;
  public bool $headersHaveBeenSent = false;
  public bool $startSucceeds = true;
  public bool $regenerationSucceeds = true;
  public bool $destructionSucceeds = true;
  public bool $cookieSucceeds = true;
  public bool $cookieParamsSucceed = true;
  public bool $iniSucceeds = true;
  public int $timestamp = 1_800_000_000;
  public string $sessionName = 'PHPSESSID';
  public string $sessionId = 'guest-session-id';
  public int $regenerationCount = 0;
  public int $destroyCount = 0;

  /** @var array<string, string> */
  public array $iniValues = [];

  /** @var array{lifetime:int,path:string,domain:string,secure:bool,httponly:bool,samesite:'Lax'|'Strict'|'None',partitioned:bool} */
  public array $params = [
    'lifetime' => 0,
    'path' => '/',
    'domain' => '',
    'secure' => true,
    'httponly' => true,
    'samesite' => 'Lax',
    'partitioned' => false,
  ];

  /** @var list<array{name:string,value:string,options:array<string, int|string|bool>}> */
  public array $cookies = [];

  private int $randomCounter = 1;

  public function status():int {
    return $this->sessionStatus;
  }

  public function headersSent():bool {
    return $this->headersHaveBeenSent;
  }

  public function name(?string $name = null):string {
    if ($name === null) {
      return $this->sessionName;
    }
    $previous = $this->sessionName;
    $this->sessionName = $name;
    return $previous;
  }

  public function id():string {
    return $this->sessionId;
  }

  public function cookieParams():array {
    return $this->params;
  }

  public function setCookieParams(array $params):bool {
    if ($this->cookieParamsSucceed) {
      $this->params = $params;
    }
    return $this->cookieParamsSucceed;
  }

  public function ini(string $name):string|false {
    return $this->iniValues[$name] ?? false;
  }

  public function setIni(string $name, string $value):bool {
    if ($this->iniSucceeds) {
      $this->iniValues[$name] = $value;
    }
    return $this->iniSucceeds;
  }

  public function start():bool {
    if ($this->startSucceeds) {
      $this->sessionStatus = PHP_SESSION_ACTIVE;
    }
    return $this->startSucceeds;
  }

  public function regenerateId(bool $deleteOldSession):bool {
    if (!$this->regenerationSucceeds) {
      return false;
    }
    ++$this->regenerationCount;
    $this->sessionId = 'rotated-session-' . $this->regenerationCount;
    return true;
  }

  public function destroy():bool {
    ++$this->destroyCount;
    if ($this->destructionSucceeds) {
      $this->sessionStatus = PHP_SESSION_NONE;
    }
    return $this->destructionSucceeds;
  }

  public function setCookie(string $name, string $value, array $options):bool {
    $this->cookies[] = ['name' => $name, 'value' => $value, 'options' => $options];
    return $this->cookieSucceeds;
  }

  public function now():int {
    return $this->timestamp;
  }

  public function randomBytes(int $length):string {
    if ($length < 1) {
      throw new \InvalidArgumentException('Random byte length must be positive.');
    }
    $seed = \hash('sha256', (string)$this->randomCounter++, true);
    return \substr(\str_repeat($seed, (int)\ceil($length / 32)), 0, $length);
  }
}
