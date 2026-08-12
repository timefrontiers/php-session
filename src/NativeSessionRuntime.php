<?php

declare(strict_types=1);

namespace TimeFrontiers;

/** @internal */
final class NativeSessionRuntime implements SessionRuntimeInterface {

  public function status():int {
    return \session_status();
  }

  public function headersSent():bool {
    return \headers_sent();
  }

  public function name(?string $name = null):string|false {
    if ($name === null) {
      $current = \session_name();
      return \is_string($current) ? $current : false;
    }

    $result = $this->withoutWarnings(static fn():string|false => \session_name($name));
    return \is_string($result) ? $result : false;
  }

  public function id():string {
    $id = \session_id();
    return \is_string($id) ? $id : '';
  }

  public function cookieParams():array {
    $params = \session_get_cookie_params();
    $sameSite = \ucfirst(\strtolower($params['samesite']));
    $paramsWithDefaults = \array_merge(['partitioned' => false], $params);
    $partitioned = $this->trueOnly($paramsWithDefaults['partitioned']);
    return [
      'lifetime' => $params['lifetime'],
      'path' => $params['path'],
      'domain' => $params['domain'],
      'secure' => $params['secure'],
      'httponly' => $params['httponly'],
      'samesite' => $sameSite,
      'partitioned' => $partitioned,
    ];
  }

  public function setCookieParams(array $params):bool {
    $result = $this->withoutWarnings(
      static fn():bool => \session_set_cookie_params($params)
    );
    return $result === true;
  }

  public function ini(string $name):string|false {
    return \ini_get($name);
  }

  public function setIni(string $name, string $value):bool {
    $result = $this->withoutWarnings(
      static fn():bool => \ini_set($name, $value) !== false
    );
    return $result === true;
  }

  public function start():bool {
    $result = $this->withoutWarnings(static fn():bool => \session_start());
    return $result === true;
  }

  public function regenerateId(bool $deleteOldSession):bool {
    $result = $this->withoutWarnings(
      static fn():bool => \session_regenerate_id($deleteOldSession)
    );
    return $result === true;
  }

  public function destroy():bool {
    $result = $this->withoutWarnings(static fn():bool => \session_destroy());
    return $result === true;
  }

  public function setCookie(string $name, string $value, array $options):bool {
    $result = $this->withoutWarnings(
      static fn():bool => \setcookie($name, $value, $options)
    );
    return $result === true;
  }

  public function now():int {
    return \time();
  }

  public function randomBytes(int $length):string {
    if ($length < 1) {
      throw new \InvalidArgumentException('Random byte length must be positive.');
    }
    return \random_bytes($length);
  }

  private function withoutWarnings(\Closure $operation):mixed {
    \set_error_handler(static fn():bool => true);
    try {
      return $operation();
    } finally {
      \restore_error_handler();
    }
  }

  private function trueOnly(mixed $value):bool {
    return $value === true;
  }
}
