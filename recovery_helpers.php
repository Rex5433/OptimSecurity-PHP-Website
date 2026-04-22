<?php

function generateRecoveryKey(): string
{
    $parts = [];
    for ($i = 0; $i < 5; $i++) {
        $parts[] = strtoupper(bin2hex(random_bytes(2)));
    }
    return implode("-", $parts);
}

function hashRecoveryKey(string $key): string
{
    return password_hash($key, PASSWORD_DEFAULT);
}

function verifyRecoveryKey(string $plainKey, string $hash): bool
{
    return password_verify($plainKey, $hash);
}

function upsertRecoveryKey(PDO $pdo, int $userId, string $plainKey): bool
{
    $hash = hashRecoveryKey($plainKey);

    $sql = '
        INSERT INTO public.account_recovery_keys (user_id, recovery_key_hash, created_at, used_at, rotated_at)
        VALUES (:user_id, :recovery_key_hash, now(), NULL, NULL)
        ON CONFLICT (user_id)
        DO UPDATE SET
            recovery_key_hash = EXCLUDED.recovery_key_hash,
            created_at = now(),
            used_at = NULL,
            rotated_at = now()
    ';

    $stmt = $pdo->prepare($sql);

    return $stmt->execute([
        'user_id' => $userId,
        'recovery_key_hash' => $hash
    ]);
}

function getRecoveryRowByUsername(PDO $pdo, string $username): ?array
{
    $sql = '
        SELECT a.id, a.username, ark.recovery_key_hash
        FROM public."Accounts" a
        INNER JOIN public.account_recovery_keys ark
            ON ark.user_id = a.id
        WHERE a.username = :username
        LIMIT 1
    ';

    $stmt = $pdo->prepare($sql);
    $stmt->execute(['username' => $username]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);

    return $row ?: null;
}

function markRecoveryKeyUsed(PDO $pdo, int $userId): void
{
    $stmt = $pdo->prepare('
        UPDATE public.account_recovery_keys
        SET used_at = now()
        WHERE user_id = :user_id
    ');
    $stmt->execute(['user_id' => $userId]);
}

function buildRecoveryFileContent(string $username, string $recoveryKey): string
{
    return
        "OPTIMSECURITY RECOVERY FILE\n" .
        "=================================\n" .
        "Username: {$username}\n" .
        "Recovery Key: {$recoveryKey}\n" .
        "=================================\n" .
        "Keep this file offline and private.\n" .
        "This key can be used to reset your password.\n";
}

function forceRecoveryFileDownload(string $username, string $recoveryKey): void
{
    $safeUsername = preg_replace('/[^a-zA-Z0-9_-]/', '_', $username);
    $filename = "optimsecurity-recovery-" . $safeUsername . ".txt";
    $content = buildRecoveryFileContent($username, $recoveryKey);

    header('Content-Type: text/plain');
    header('Content-Disposition: attachment; filename="' . $filename . '"');
    header('Content-Length: ' . strlen($content));
    echo $content;
    exit;
}
