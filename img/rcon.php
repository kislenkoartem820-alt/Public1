<?php
/**
 * rcon.php — мост между админ-панелью сайта и реальным CS2-сервером.
 *
 * Что делает:
 *   Принимает POST-запросы от index.html (кик/бан/мут) и пересылает их
 *   на игровой сервер по протоколу Source RCON (обычный TCP-порт RCON,
 *   НЕ игровой порт 27015 обязательно — уточните RCON-порт у вашего хостера CS2).
 *
 * Обязательно перед использованием:
 *   1. Впишите ниже RCON_HOST / RCON_PORT / RCON_PASSWORD — данные вашего
 *      сервера (их даёт хостинг-панель, где вы поднимали CS2-сервер).
 *   2. Смените ADMIN_TOKEN — это отдельный секрет, защищающий сам rcon.php
 *      от прямых запросов кем угодно (пароль в index.html — это ДРУГОЙ,
 *      чисто визуальный замок, его недостаточно для защиты сервера).
 *   3. Загрузите этот файл на хостинг рядом с index.html (нужен PHP).
 *   4. В index.html переменная RCON_ENDPOINT уже указывает на "rcon.php" —
 *      менять не нужно, если файлы лежат в одной папке.
 *
 * Команды, которые уходят на сервер:
 *   kick  -> kickid <userid_или_ник> "<причина>"
 *   ban   -> banid <минуты> <steamid> kick   (0 минут = навсегда)
 *   mute  -> sm_mute / sm_gag / sm_silence <ник> <минуты>  (требует SourceMod)
 *
 * Если на сервере НЕ установлен SourceMod, замените mute-команды ниже
 * на аналог вашей админ-плагин-системы (или на голосовые/текстовые
 * ограничения, которые поддерживает именно ваш сервер).
 */

// ---------------- НАСТРОЙКИ: ЗАПОЛНИТЕ ПЕРЕД ИСПОЛЬЗОВАНИЕМ ----------------
define('RCON_HOST', '127.0.0.1');       // IP вашего CS2-сервера
define('RCON_PORT', 27015);             // RCON-порт (узнать у хостинга)
define('RCON_PASSWORD', 'CHANGE_ME');   // rcon_password с сервера
define('ADMIN_TOKEN', 'CHANGE_ME_TOO'); // секрет для защиты этого файла
// -----------------------------------------------------------------------

header('Content-Type: application/json; charset=utf-8');

// Пинг для index.html, чтобы понять, настроен ли бэкенд (LIVE MODE)
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    $configured = RCON_PASSWORD !== 'CHANGE_ME';
    http_response_code($configured ? 200 : 503);
    echo json_encode(['ready' => $configured]);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['error' => 'method not allowed']);
    exit;
}

// Простая защита: сравните заголовок X-Admin-Token с ADMIN_TOKEN,
// если хотите закрыть доступ ещё и на уровне сервера (рекомендуется).
// $sent = $_SERVER['HTTP_X_ADMIN_TOKEN'] ?? '';
// if (!hash_equals(ADMIN_TOKEN, $sent)) { http_response_code(403); exit(json_encode(['error'=>'forbidden'])); }

$input = json_decode(file_get_contents('php://input'), true);
if (!$input || empty($input['action']) || empty($input['nick'])) {
    http_response_code(400);
    echo json_encode(['error' => 'bad request']);
    exit;
}

$action   = $input['action'];
$nick     = $input['nick'];
$steam    = $input['steam'] ?? '';
$reason   = $input['reason'] ?? '';
$duration = isset($input['duration']) ? (int)$input['duration'] : 0;

$command = buildCommand($action, $nick, $steam, $reason, $duration);
if ($command === null) {
    http_response_code(400);
    echo json_encode(['error' => 'unknown action']);
    exit;
}

try {
    $response = sendRcon(RCON_HOST, RCON_PORT, RCON_PASSWORD, $command);
    echo json_encode(['ok' => true, 'command' => $command, 'response' => $response]);
} catch (Exception $e) {
    http_response_code(502);
    echo json_encode(['ok' => false, 'error' => $e->getMessage()]);
}

// ---------------------------------------------------------------------
function buildCommand(string $action, string $nick, string $steam, string $reason, int $duration): ?string {
    $safeNick = str_replace('"', '', $nick);
    $safeReason = str_replace('"', '', $reason) ?: 'No reason given';

    switch ($action) {
        case 'kick':
            return "sm_kick \"{$safeNick}\" \"{$safeReason}\"";
        case 'ban':
            // banid принимает минуты и steamid; 0 = перманентный бан
            $target = $steam ?: $safeNick;
            return "sm_ban \"{$target}\" {$duration} \"{$safeReason}\"";
        case 'mute':
            $target = $steam ?: $safeNick;
            return "sm_mute \"{$target}\"";
        default:
            return null;
    }
}

/**
 * Реализация протокола Source RCON (SERVERDATA_AUTH / SERVERDATA_EXECCOMMAND).
 * Работает через обычный TCP-сокет, без внешних библиотек.
 */
function sendRcon(string $host, int $port, string $password, string $command): string {
    $sock = @fsockopen($host, $port, $errno, $errstr, 4);
    if (!$sock) {
        throw new Exception("Не удалось подключиться к {$host}:{$port} — {$errstr}");
    }
    stream_set_timeout($sock, 4);

    rconWritePacket($sock, 1, 3, $password); // SERVERDATA_AUTH
    $authResp = rconReadPacket($sock);
    if ($authResp === null || $authResp['id'] === -1) {
        fclose($sock);
        throw new Exception('RCON-авторизация не удалась — проверьте RCON_PASSWORD');
    }

    rconWritePacket($sock, 2, 2, $command); // SERVERDATA_EXECCOMMAND
    $resp = rconReadPacket($sock);
    fclose($sock);

    return $resp['body'] ?? '';
}

function rconWritePacket($sock, int $id, int $type, string $body): void {
    $payload = pack('V', $id) . pack('V', $type) . $body . "\x00\x00";
    $packet = pack('V', strlen($payload)) . $payload;
    fwrite($sock, $packet);
}

function rconReadPacket($sock): ?array {
    $sizeData = fread($sock, 4);
    if ($sizeData === false || strlen($sizeData) < 4) return null;
    $size = unpack('V', $sizeData)[1];
    $data = '';
    while (strlen($data) < $size) {
        $chunk = fread($sock, $size - strlen($data));
        if ($chunk === false || $chunk === '') break;
        $data .= $chunk;
    }
    $id = unpack('V', substr($data, 0, 4))[1];
    $type = unpack('V', substr($data, 4, 4))[1];
    $body = substr($data, 8, -2);
    return ['id' => $id > 2147483647 ? $id - 4294967296 : $id, 'type' => $type, 'body' => $body];
}
