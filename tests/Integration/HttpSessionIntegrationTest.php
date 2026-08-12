<?php

declare(strict_types=1);

namespace TimeFrontiers\Tests\Integration;

use PHPUnit\Framework\TestCase;

final class HttpSessionIntegrationTest extends TestCase {

  /** @var resource|null */
  private $process = null;

  /** @var array<int, resource> */
  private array $pipes = [];

  private string $savePath;
  private string $baseUrl;

  protected function setUp():void {
    parent::setUp();
    if (!\function_exists('proc_open')) {
      self::markTestSkipped('proc_open is required for the HTTP integration test.');
    }

    $this->savePath = \sys_get_temp_dir()
      . DIRECTORY_SEPARATOR
      . 'timefrontiers-session-http-'
      . \bin2hex(\random_bytes(8));
    self::assertTrue(\mkdir($this->savePath, 0700));

    $socket = \stream_socket_server('tcp://127.0.0.1:0', $errorCode, $errorMessage);
    if (!\is_resource($socket)) {
      self::fail($errorMessage ?? 'Unable to allocate a loopback port.');
    }
    $address = \stream_socket_get_name($socket, false);
    self::assertIsString($address);
    \fclose($socket);
    $port = (int)\substr($address, (int)\strrpos($address, ':') + 1);
    $this->baseUrl = 'http://127.0.0.1:' . $port;

    $command = [
      PHP_BINARY,
      '-S',
      '127.0.0.1:' . $port,
      'tests/Fixtures/http-router.php',
    ];
    $descriptors = [
      0 => ['pipe', 'r'],
      1 => ['pipe', 'w'],
      2 => ['pipe', 'w'],
    ];
    $environment = \getenv();
    $environment['TF_SESSION_SAVE_PATH'] = $this->savePath;
    $process = \proc_open(
      $command,
      $descriptors,
      $this->pipes,
      \dirname(__DIR__, 2),
      $environment
    );
    if (!\is_resource($process)) {
      self::fail('Unable to start the loopback PHP server.');
    }
    $this->process = $process;
    foreach ($this->pipes as $pipe) {
      \stream_set_blocking($pipe, false);
    }

    $ready = false;
    for ($attempt = 0; $attempt < 50; ++$attempt) {
      try {
        $this->request('/guest');
        $ready = true;
        break;
      } catch (\RuntimeException) {
        \usleep(50_000);
      }
    }
    self::assertTrue($ready, 'The loopback PHP server did not become ready.');
  }

  protected function tearDown():void {
    if (\is_resource($this->process)) {
      \proc_terminate($this->process);
      for ($attempt = 0; $attempt < 20; ++$attempt) {
        $status = \proc_get_status($this->process);
        if (!$status['running']) {
          break;
        }
        \usleep(50_000);
      }
      $status = \proc_get_status($this->process);
      if ($status['running']) {
        \proc_terminate($this->process, 9);
      }
      foreach ($this->pipes as $pipe) {
        if (\is_resource($pipe)) {
          \fclose($pipe);
        }
      }
      \proc_close($this->process);
    }

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

  public function testHttpLoginRotatesAndInvalidatesPreLoginCookie():void {
    $guest = $this->request('/guest');
    $guestCookie = $this->cookieFromHeaders($guest['headers']);
    self::assertFalse($guest['json']['logged_in']);

    $login = $this->request('/login', $guestCookie);
    $authenticatedCookie = $this->cookieFromHeaders($login['headers']);
    self::assertTrue($login['json']['ok']);
    self::assertTrue($login['json']['logged_in']);
    self::assertNotSame($guestCookie, $authenticatedCookie);

    $authenticated = $this->request('/status', $authenticatedCookie);
    self::assertTrue($authenticated['json']['logged_in']);

    $fixed = $this->request('/status', $guestCookie);
    self::assertFalse($fixed['json']['logged_in']);
  }

  /**
   * @return array{json:array<string,mixed>,headers:list<string>}
   */
  private function request(string $path, ?string $cookie = null):array {
    $headers = ['Connection: close'];
    if ($cookie !== null) {
      $headers[] = 'Cookie: ' . $cookie;
    }
    $context = \stream_context_create([
      'http' => [
        'method' => 'GET',
        'header' => \implode("\r\n", $headers),
        'ignore_errors' => true,
        'timeout' => 2,
      ],
    ]);
    $body = @\file_get_contents($this->baseUrl . $path, false, $context);
    if ($body === false) {
      throw new \RuntimeException('HTTP request failed.');
    }

    $responseHeaders = \http_get_last_response_headers();
    if (!\is_array($responseHeaders)) {
      $responseHeaders = [];
    }
    try {
      $json = \json_decode($body, true, 512, JSON_THROW_ON_ERROR);
    } catch (\JsonException $cause) {
      throw new \RuntimeException('Invalid HTTP JSON: ' . $body, 0, $cause);
    }
    if (!\is_array($json)) {
      throw new \RuntimeException('Invalid HTTP response.');
    }
    $normalized = [];
    foreach ($json as $key => $value) {
      if (!\is_string($key)) {
        throw new \RuntimeException('Invalid HTTP response keys.');
      }
      $normalized[$key] = $value;
    }
    return ['json' => $normalized, 'headers' => $responseHeaders];
  }

  /** @param list<string> $headers */
  private function cookieFromHeaders(array $headers):string {
    foreach ($headers as $header) {
      if (\preg_match('/^Set-Cookie:\s*(TFSESSID=[^;]+)/i', $header, $matches) === 1) {
        return $matches[1];
      }
    }
    self::fail('The response did not include the expected session cookie.');
  }
}
