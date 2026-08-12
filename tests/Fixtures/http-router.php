<?php

declare(strict_types=1);

use TimeFrontiers\AccessGroup;
use TimeFrontiers\AccessRank;
use TimeFrontiers\Session;
use TimeFrontiers\SessionConfig;

require \dirname(__DIR__, 2) . '/vendor/autoload.php';

$savePath = \getenv('TF_SESSION_SAVE_PATH');
if (\is_string($savePath) && $savePath !== '') {
  \ini_set('session.save_path', $savePath);
}

$session = new Session(config: new SessionConfig(
  cookieName: 'TFSESSID',
  externalRequestIsSecure: false,
  cookieSecure: false,
  allowInsecureDevelopment: true
));

$requestUri = $_SERVER['REQUEST_URI'] ?? '/';
if (!\is_string($requestUri)) {
  $requestUri = '/';
}
$path = \parse_url($requestUri, PHP_URL_PATH);
$response = [
  'ok' => true,
  'logged_in' => $session->isLoggedIn(),
  'session_id' => \session_id(),
];

if ($path === '/login') {
  $response['ok'] = $session->login((object)[
    'id' => 42,
    'uniqueid' => '01234567890',
    'name' => 'Ada',
    'access_group' => AccessGroup::ADMIN,
    'access_rank' => AccessRank::ADMIN,
  ]);
  $response['logged_in'] = $session->isLoggedIn();
  $response['session_id'] = \session_id();
} elseif ($path === '/logout') {
  $response['ok'] = $session->logout();
  $response['logged_in'] = $session->isLoggedIn();
  $response['session_id'] = \session_id();
}

\header('Content-Type: application/json; charset=UTF-8');
echo \json_encode($response, JSON_THROW_ON_ERROR);
