<?php

function randomBase32Secret(int $length = 32): string
{
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $maxIndex = strlen($alphabet) - 1;
    $secret = '';

    for ($i = 0; $i < $length; $i++) {
        $secret .= $alphabet[random_int(0, $maxIndex)];
    }

    return $secret;
}

function base32Decode(string $input): string
{
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $input = strtoupper(trim($input));
    $input = preg_replace('/[^A-Z2-7]/', '', $input);

    if ($input === '') {
        return '';
    }

    $bits = '';
    $output = '';
    $len = strlen($input);

    for ($i = 0; $i < $len; $i++) {
        $char = $input[$i];
        $pos = strpos($alphabet, $char);

        if ($pos === false) {
            continue;
        }

        $bits .= str_pad(decbin($pos), 5, '0', STR_PAD_LEFT);
    }

    $bitLen = strlen($bits);

    for ($i = 0; $i + 8 <= $bitLen; $i += 8) {
        $output .= chr(bindec(substr($bits, $i, 8)));
    }

    return $output;
}

function getTotpCode(
    string $secret,
    ?int $timestamp = null,
    int $digits = 6,
    int $period = 30,
    string $algo = 'sha1'
): string {
    if ($timestamp === null) {
        $timestamp = time();
    }

    $secretKey = base32Decode($secret);

    if ($secretKey === '') {
        return str_repeat('0', $digits);
    }

    $counter = (int) floor($timestamp / $period);
    $binaryCounter = pack('N2', 0, $counter);

    $hash = hash_hmac($algo, $binaryCounter, $secretKey, true);

    $offset = ord(substr($hash, -1)) & 0x0F;
    $part = substr($hash, $offset, 4);

    $value = unpack('N', $part)[1] & 0x7FFFFFFF;
    $mod = 10 ** $digits;

    return str_pad((string) ($value % $mod), $digits, '0', STR_PAD_LEFT);
}

function verifyTotpCode(
    string $secret,
    string $code,
    int $window = 1,
    int $digits = 6,
    int $period = 30,
    string $algo = 'sha1'
): bool {
    $code = trim($code);

    if (!preg_match('/^\d{' . $digits . '}$/', $code)) {
        return false;
    }

    $now = time();

    for ($i = -$window; $i <= $window; $i++) {
        $testTime = $now + ($i * $period);
        $expected = getTotpCode($secret, $testTime, $digits, $period, $algo);

        if (hash_equals($expected, $code)) {
            return true;
        }
    }

    return false;
}

function generateBackupCodes(int $count = 8): array
{
    $codes = [];

    for ($i = 0; $i < $count; $i++) {
        $codes[] = strtoupper(bin2hex(random_bytes(4)));
    }

    return $codes;
}

function hashBackupCodes(array $codes): string
{
    $hashed = [];

    foreach ($codes as $code) {
        $hashed[] = password_hash($code, PASSWORD_DEFAULT);
    }

    return json_encode($hashed);
}

function verifyBackupCode(string $inputCode, $storedJson): array
{
    $inputCode = strtoupper(trim($inputCode));
    $codes = json_decode((string) $storedJson, true);

    if (!is_array($codes)) {
        return [false, json_encode([])];
    }

    foreach ($codes as $index => $hash) {
        if (password_verify($inputCode, $hash)) {
            unset($codes[$index]);
            $codes = array_values($codes);
            return [true, json_encode($codes)];
        }
    }

    return [false, json_encode($codes)];
}

function consumeBackupCode(PDO $pdo, int $userId, string $inputCode): bool
{
    $stmt = $pdo->prepare('
        SELECT twofa_backup_codes
        FROM "Accounts"
        WHERE id = :id
        LIMIT 1
    ');
    $stmt->execute(['id' => $userId]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$row) {
        return false;
    }

    [$valid, $newJson] = verifyBackupCode($inputCode, $row["twofa_backup_codes"] ?? '[]');

    if (!$valid) {
        return false;
    }

    $update = $pdo->prepare('
        UPDATE "Accounts"
        SET twofa_backup_codes = :codes
        WHERE id = :id
    ');
    $update->execute([
        'codes' => $newJson,
        'id' => $userId
    ]);

    return true;
}