<?php

declare(strict_types=1);

namespace TimeFrontiers;

/**
 * Native PHP session boundary.
 *
 * @internal This interface exists to make security-critical failure paths
 * deterministic in tests. Applications should normally use the native runtime.
 */
interface SessionRuntimeInterface {

  public function status():int;

  public function headersSent():bool;

  public function name(?string $name = null):string|false;

  public function id():string;

  /** @return array{lifetime:int,path:string,domain:string,secure:bool,httponly:bool,samesite:'Lax'|'Strict'|'None',partitioned:bool} */
  public function cookieParams():array;

  /** @param array{lifetime:int,path:string,domain:string,secure:bool,httponly:bool,samesite:'Lax'|'Strict'|'None',partitioned:bool} $params */
  public function setCookieParams(array $params):bool;

  public function ini(string $name):string|false;

  public function setIni(string $name, string $value):bool;

  public function start():bool;

  public function regenerateId(bool $deleteOldSession):bool;

  public function destroy():bool;

  /**
   * @param array{expires:int,path:string,domain:string,secure:bool,httponly:bool,samesite:'Lax'|'Strict'|'None',partitioned:bool} $options
   */
  public function setCookie(string $name, string $value, array $options):bool;

  public function now():int;

  public function randomBytes(int $length):string;
}
