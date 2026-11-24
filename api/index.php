<?php
declare(strict_types=1);

require_once dirname(__DIR__) . '/config/database.php';

$secureCookie = filter_var(getenv('APP_SESSION_SECURE') ?: 'false', FILTER_VALIDATE_BOOLEAN);
session_set_cookie_params([
    'lifetime' => 0,
    'path' => '/',
    'secure' => $secureCookie,
    'httponly' => true,
    'samesite' => 'Lax',
]);
session_start();

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');

function respond(int $status, array $payload): never
{
    http_response_code($status);
    echo json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    exit;
}

function requestData(): array
{
    $raw = file_get_contents('php://input');
    if ($raw === false || strlen($raw) > 2_500_000) {
        respond(413, ['error' => 'Request is too large']);
    }
    $data = json_decode($raw, true);
    if (!is_array($data)) {
        respond(400, ['error' => 'Expected a JSON object']);
    }
    return $data;
}

function requiredString(array $data, string $key, int $maxLength): string
{
    $value = $data[$key] ?? null;
    if (!is_string($value) || trim($value) === '' || strlen($value) > $maxLength) {
        respond(422, ['error' => "Invalid {$key}"]);
    }
    return $value;
}

function roomIdFromPath(string $path): ?string
{
    return preg_match('~^/api/vaults/([0-9a-f-]{36})(?:/(?:unlock|contents(?:/([0-9a-f-]{36}))?|files(?:/([0-9a-f-]{36}))?))?/?$~i', $path, $m)
        ? strtolower($m[1])
        : null;
}

function requireRoomAccess(string $roomId): void
{
    if (empty($_SESSION['rooms'][$roomId])) {
        respond(401, ['error' => 'Unlock this room first']);
    }
}

function requireCsrf(): void
{
    $provided = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
    $expected = $_SESSION['csrf_token'] ?? '';
    if (!is_string($provided) || !is_string($expected) || $expected === '' || !hash_equals($expected, $provided)) {
        respond(403, ['error' => 'Session token is missing or expired']);
    }
}

function newId(): string
{
    return sprintf('%04x%04x-%04x-4%03x-%04x-%04x%08x', random_int(0, 65535), random_int(0, 65535), random_int(0, 65535), random_int(0, 4095), random_int(0, 16383) | 0x8000, random_int(0, 65535), random_int(0, 0xffffffff));
}

function filePath(string $id): string
{
    return rtrim(getenv('FILE_STORAGE_PATH') ?: dirname(__DIR__) . '/storage/files', '/\\') . DIRECTORY_SEPARATOR . $id . '.bin';
}

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
$appBase = rtrim(str_replace('\\', '/', dirname(dirname($_SERVER['SCRIPT_NAME'] ?? '/api/index.php'))), '/');
if ($appBase !== '' && str_starts_with($path, $appBase . '/')) {
    $path = substr($path, strlen($appBase));
}

try {
    $pdo = database();
    if ($path === '/api/vaults' && $method === 'POST') {
        $data = requestData();
        $name = trim(requiredString($data, 'name', 100));
        $password = requiredString($data, 'password', 1024);
        if (strlen($password) < 1) {
            respond(422, ['error' => 'Password is required']);
        }

        $id = sprintf('%04x%04x-%04x-4%03x-%04x-%04x%08x', random_int(0, 65535), random_int(0, 65535), random_int(0, 65535), random_int(0, 4095), random_int(0, 16383) | 0x8000, random_int(0, 65535), random_int(0, 0xffffffff));
        $salt = random_bytes(16);
        $passwordDigest = hash('sha256', $password);
        $stmt = $pdo->prepare('INSERT INTO rooms (id, name, password_hash, encryption_salt) VALUES (?, ?, ?, ?)');
        try {
            $stmt->execute([$id, $name, password_hash($passwordDigest, PASSWORD_DEFAULT), $salt]);
        } catch (PDOException $e) {
            if ($e->getCode() === '23000') {
                respond(409, ['error' => 'Room name already taken']);
            }
            throw $e;
        }

        session_regenerate_id(true);
        $_SESSION['rooms'][$id] = true;
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        respond(201, ['room' => ['id' => $id, 'name' => $name, 'salt' => base64_encode($salt)], 'csrfToken' => $_SESSION['csrf_token']]);
    }

    if ($path === '/api/vaults/enter' && $method === 'POST') {
        $data = requestData();
        $name = trim(requiredString($data, 'name', 100));
        $password = requiredString($data, 'password', 1024);
        $stmt = $pdo->prepare('SELECT id, name, password_hash, encryption_salt FROM rooms WHERE name = ? LIMIT 1');
        $stmt->execute([$name]);
        $room = $stmt->fetch();
        if (!$room || !password_verify(hash('sha256', $password), $room['password_hash'])) {
            respond(401, ['error' => 'Room name or password is incorrect']);
        }

        session_regenerate_id(true);
        $_SESSION['rooms'] = [$room['id'] => true];
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        respond(200, [
            'room' => ['id' => $room['id'], 'name' => $room['name'], 'salt' => base64_encode($room['encryption_salt'])],
            'csrfToken' => $_SESSION['csrf_token'],
        ]);
    }

    $roomId = roomIdFromPath($path);
    if ($roomId !== null) {
        if (preg_match('~/unlock/?$~', $path) && $method === 'POST') {
            $data = requestData();
            $password = requiredString($data, 'password', 1024);
            $stmt = $pdo->prepare('SELECT id, name, password_hash, encryption_salt FROM rooms WHERE id = ? LIMIT 1');
            $stmt->execute([$roomId]);
            $room = $stmt->fetch();
            if (!$room || !password_verify(hash('sha256', $password), $room['password_hash'])) {
                respond(401, ['error' => 'Room password is incorrect']);
            }
            session_regenerate_id(true);
            $_SESSION['rooms'] = [$roomId => true];
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
            respond(200, [
                'room' => ['id' => $room['id'], 'name' => $room['name'], 'salt' => base64_encode($room['encryption_salt'])],
                'csrfToken' => $_SESSION['csrf_token'],
            ]);
        }
        requireRoomAccess($roomId);
        if (preg_match('~/files(?:/([0-9a-f-]{36}))?/?$~i', $path, $fileMatch)) {
            $fileId = isset($fileMatch[1]) ? strtolower($fileMatch[1]) : null;
            if ($fileId === null && $method === 'GET') {
                $stmt = $pdo->prepare('SELECT id, encrypted_name, name_iv, file_iv, byte_size, created_at FROM files WHERE room_id = ? ORDER BY created_at DESC');
                $stmt->execute([$roomId]);
                respond(200, ['files' => $stmt->fetchAll()]);
            }
            if ($fileId === null && $method === 'POST') {
                requireCsrf();
                $size = (int)($_SERVER['CONTENT_LENGTH'] ?? 0);
                if ($size < 16 || $size > 25 * 1024 * 1024) respond(413, ['error' => 'Encrypted file must be 16 bytes to 25 MB']);
                $encryptedName = $_SERVER['HTTP_X_FILE_NAME'] ?? '';
                $nameIv = $_SERVER['HTTP_X_NAME_IV'] ?? '';
                $fileIv = $_SERVER['HTTP_X_FILE_IV'] ?? '';
                if (!preg_match('/^[A-Za-z0-9_-]{1,4096}$/', $encryptedName) || !preg_match('/^[A-Za-z0-9_-]{16}$/', $nameIv) || !preg_match('/^[A-Za-z0-9_-]{16}$/', $fileIv)) respond(422, ['error' => 'Invalid encrypted file metadata']);
                $id = newId();
                $dir = getenv('FILE_STORAGE_PATH') ?: dirname(__DIR__) . '/storage/files';
                if (!is_dir($dir) && !mkdir($dir, 0700, true) && !is_dir($dir)) respond(500, ['error' => 'File storage unavailable']);
                $temp = tempnam($dir, 'upload-');
                $input = fopen('php://input', 'rb'); $output = fopen($temp, 'wb');
                if (!$input || !$output) respond(500, ['error' => 'Could not receive file']);
                stream_copy_to_stream($input, $output, 25 * 1024 * 1024 + 1);
                fclose($input); fclose($output);
                if (filesize($temp) !== $size) { unlink($temp); respond(400, ['error' => 'File upload was incomplete']); }
                $stmt = $pdo->prepare('INSERT INTO files (id, room_id, encrypted_name, name_iv, file_iv, mime_type, byte_size) VALUES (?, ?, ?, ?, ?, ?, ?)');
                $stmt->execute([$id, $roomId, $encryptedName, $nameIv, $fileIv, 'application/octet-stream', $size]);
                rename($temp, filePath($id));
                respond(201, ['id' => $id]);
            }
            if ($fileId !== null) {
                $stmt = $pdo->prepare('SELECT id, byte_size FROM files WHERE id = ? AND room_id = ?');
                $stmt->execute([$fileId, $roomId]); $file = $stmt->fetch();
                if (!$file) respond(404, ['error' => 'File not found']);
                if ($method === 'GET') {
                    header('Content-Type: application/octet-stream');
                    header('Content-Length: ' . $file['byte_size']);
                    header('Content-Disposition: attachment; filename="encrypted.bin"');
                    readfile(filePath($fileId)); exit;
                }
                if ($method === 'DELETE') {
                    requireCsrf();
                    $pdo->prepare('DELETE FROM files WHERE id = ? AND room_id = ?')->execute([$fileId, $roomId]);
                    if (is_file(filePath($fileId))) unlink(filePath($fileId));
                    respond(200, ['ok' => true]);
                }
            }
        }
        $contentId = null;
        if (preg_match('~/contents/([0-9a-f-]{36})/?$~i', $path, $contentMatch)) {
            $contentId = strtolower($contentMatch[1]);
        }

        if ($contentId === null && preg_match('~/contents/?$~', $path)) {
            if ($method === 'GET') {
                $stmt = $pdo->prepare('SELECT id, ciphertext, iv, created_at, updated_at FROM contents WHERE room_id = ? ORDER BY created_at DESC');
                $stmt->execute([$roomId]);
                respond(200, ['contents' => $stmt->fetchAll()]);
            }
            if ($method === 'POST') {
                requireCsrf();
                $data = requestData();
                $ciphertext = requiredString($data, 'ciphertext', 2_300_000);
                $iv = requiredString($data, 'iv', 32);
                if (!preg_match('/^[A-Za-z0-9_-]+$/', $ciphertext) || !preg_match('/^[A-Za-z0-9_-]{16}$/', $iv)) {
                    respond(422, ['error' => 'Invalid encrypted content']);
                }
                $id = sprintf('%04x%04x-%04x-4%03x-%04x-%04x%08x', random_int(0, 65535), random_int(0, 65535), random_int(0, 65535), random_int(0, 4095), random_int(0, 16383) | 0x8000, random_int(0, 65535), random_int(0, 0xffffffff));
                $stmt = $pdo->prepare('INSERT INTO contents (id, room_id, ciphertext, iv) VALUES (?, ?, ?, ?)');
                $stmt->execute([$id, $roomId, $ciphertext, $iv]);
                respond(201, ['id' => $id]);
            }
        }

        if ($contentId !== null) {
            if ($method === 'PUT') {
                requireCsrf();
                $data = requestData();
                $ciphertext = requiredString($data, 'ciphertext', 2_300_000);
                $iv = requiredString($data, 'iv', 32);
                if (!preg_match('/^[A-Za-z0-9_-]+$/', $ciphertext) || !preg_match('/^[A-Za-z0-9_-]{16}$/', $iv)) {
                    respond(422, ['error' => 'Invalid encrypted content']);
                }
                $stmt = $pdo->prepare('UPDATE contents SET ciphertext = ?, iv = ? WHERE id = ? AND room_id = ?');
                $stmt->execute([$ciphertext, $iv, $contentId, $roomId]);
                if ($stmt->rowCount() === 0) {
                    $check = $pdo->prepare('SELECT 1 FROM contents WHERE id = ? AND room_id = ?');
                    $check->execute([$contentId, $roomId]);
                    if (!$check->fetchColumn()) respond(404, ['error' => 'Content not found']);
                }
                respond(200, ['ok' => true]);
            }
            if ($method === 'DELETE') {
                requireCsrf();
                $stmt = $pdo->prepare('DELETE FROM contents WHERE id = ? AND room_id = ?');
                $stmt->execute([$contentId, $roomId]);
                if ($stmt->rowCount() === 0) respond(404, ['error' => 'Content not found']);
                respond(200, ['ok' => true]);
            }
        }
    }

    respond(404, ['error' => 'Endpoint not found']);
} catch (Throwable $e) {
    error_log((string) $e);
    respond(500, ['error' => 'Server error']);
}
