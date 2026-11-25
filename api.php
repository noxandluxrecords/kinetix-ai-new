<?php
declare(strict_types=1);
session_set_cookie_params(['lifetime' => 2592000, 'path' => '/', 'secure' => !empty($_SERVER['HTTPS']), 'httponly' => true, 'samesite' => 'Lax']);
session_start();
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

$dir = __DIR__ . '/data';
$usersFile = $dir . '/users.json';

function out(array $d, int $c = 200): void { http_response_code($c); echo json_encode($d); exit; }
function readJson(string $f): array { $r = @file_get_contents($f); $j = $r ? json_decode($r, true) : null; return is_array($j) ? $j : []; }
function writeJson(string $f, array $d): void { file_put_contents($f, json_encode($d, JSON_UNESCAPED_UNICODE), LOCK_EX); }
function makeHash(string $p): array { $s = bin2hex(random_bytes(16)); return ['salt' => $s, 'iter' => 210000, 'hash' => hash_pbkdf2('sha256', $p, $s, 210000, 64)]; }
function checkPw(array $users, string $u, string $p): bool {
    if (!isset($users[$u])) { hash_pbkdf2('sha256', $p, 'x', 210000, 64); return false; }
    $r = $users[$u];
    return hash_equals($r['hash'], hash_pbkdf2('sha256', $p, $r['salt'], (int)$r['iter'], 64));
}

$action = $_GET['action'] ?? '';
$in = json_decode(file_get_contents('php://input') ?: '{}', true);
if (!is_array($in)) $in = [];

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_SERVER['HTTP_X_REQUESTED_WITH'] ?? '') !== 'kinetix') out(['ok' => false, 'error' => 'Solicitud no válida'], 400);

$users = readJson($usersFile);
$user = $_SESSION['user'] ?? null;
$stateFile = $user ? $dir . '/state_' . md5(strtolower($user)) . '.json' : null;

switch ($action) {
    case 'login':
        // límite de intentos: 8 fallos / 15 min por IP
        $ip = $_SERVER['REMOTE_ADDR'] ?? '0';
        $attFile = $dir . '/attempts.json';
        $att = readJson($attFile);
        $now = time();
        $att[$ip] = array_values(array_filter($att[$ip] ?? [], fn($t) => $t > $now - 900));
        if (count($att[$ip]) >= 8) out(['ok' => false, 'error' => 'Demasiados intentos. Espera 15 minutos.'], 429);
        $u = trim((string)($in['username'] ?? ''));
        $p = (string)($in['password'] ?? '');
        if ($u !== '' && checkPw($users, $u, $p)) {
            session_regenerate_id(true);
            $_SESSION['user'] = $u;
            unset($att[$ip]); writeJson($attFile, $att);
            out(['ok' => true, 'user' => $u]);
        }
        $att[$ip][] = $now; writeJson($attFile, $att);
        out(['ok' => false, 'error' => 'Usuario o contraseña incorrectos.'], 401);

    case 'logout':
        $_SESSION = []; session_destroy();
        out(['ok' => true]);

    case 'me':
        out($user ? ['ok' => true, 'user' => $user] : ['ok' => false], $user ? 200 : 401);

    case 'load':
        if (!$user) out(['ok' => false], 401);
        $s = readJson($stateFile);
        out(['ok' => true, 'state' => $s ?: null]);

    case 'save':
        if (!$user) out(['ok' => false], 401);
        $st = $in['state'] ?? null;
        if (!is_array($st)) out(['ok' => false, 'error' => 'Estado inválido'], 400);
        $json = json_encode($st, JSON_UNESCAPED_UNICODE);
        if (strlen($json) > 2000000) out(['ok' => false, 'error' => 'Estado demasiado grande'], 413);
        file_put_contents($stateFile, $json, LOCK_EX);
        out(['ok' => true]);

    case 'reset':
        if (!$user) out(['ok' => false], 401);
        @unlink($stateFile);
        out(['ok' => true]);

    case 'passwd':
        if (!$user) out(['ok' => false], 401);
        $new = (string)($in['new'] ?? '');
        if (!checkPw($users, $user, (string)($in['old'] ?? ''))) out(['ok' => false, 'error' => 'La contraseña actual no coincide'], 403);
        if (strlen($new) < 10) out(['ok' => false, 'error' => 'La nueva contraseña debe tener al menos 10 caracteres'], 400);
        $users[$user] = makeHash($new);
        writeJson($usersFile, $users);
        out(['ok' => true]);

    default:
        out(['ok' => false, 'error' => 'Acción desconocida'], 404);
}
