<?php
session_start();
header("Content-Type: application/json");

if (!isset($_SESSION["user_id"])) {
    http_response_code(401);
    echo json_encode([
        "ok" => false,
        "error" => "Not logged in."
    ]);
    exit;
}

if (
    empty($_SERVER["HTTP_X_CSRF_TOKEN"]) ||
    empty($_SESSION["csrf_token"]) ||
    !hash_equals($_SESSION["csrf_token"], $_SERVER["HTTP_X_CSRF_TOKEN"])
) {
    http_response_code(403);
    echo json_encode([
        "ok" => false,
        "error" => "Invalid CSRF token."
    ]);
    exit;
}

require_once "db.php";
require_once __DIR__ . "/recovery_helpers.php";

if (!$pdo) {
    http_response_code(500);
    echo json_encode([
        "ok" => false,
        "error" => "Database connection failed."
    ]);
    exit;
}

$body = json_decode(file_get_contents("php://input"), true);

if (!is_array($body)) {
    http_response_code(400);
    echo json_encode([
        "ok" => false,
        "error" => "Invalid JSON payload."
    ]);
    exit;
}

$userId = (int) $_SESSION["user_id"];
$vaultSalt = trim((string) ($body["vault_salt"] ?? ""));
$vaultIterations = (int) ($body["vault_iterations"] ?? 0);
$vaultKeyCheck = trim((string) ($body["vault_key_check"] ?? ""));
$wrappedVaultKey = trim((string) ($body["wrapped_vault_key"] ?? ""));
$wrappedVaultKeyIv = trim((string) ($body["wrapped_vault_key_iv"] ?? ""));
$wrappedVaultKeyRecovery = trim((string) ($body["wrapped_vault_key_recovery"] ?? ""));
$wrappedVaultKeyRecoveryIv = trim((string) ($body["wrapped_vault_key_recovery_iv"] ?? ""));
$plainRecoveryKey = trim((string) ($body["plain_recovery_key"] ?? ""));

if (
    $vaultSalt === "" ||
    $vaultIterations <= 0 ||
    $vaultKeyCheck === "" ||
    $wrappedVaultKey === "" ||
    $wrappedVaultKeyIv === "" ||
    $wrappedVaultKeyRecovery === "" ||
    $wrappedVaultKeyRecoveryIv === ""
) {
    http_response_code(400);
    echo json_encode([
        "ok" => false,
        "error" => "Missing vault profile fields."
    ]);
    exit;
}

try {
    $pdo->beginTransaction();

    $stmt = $pdo->prepare('
        INSERT INTO public.vault_profile (
            user_id,
            vault_salt,
            vault_iterations,
            vault_key_check,
            wrapped_vault_key,
            wrapped_vault_key_iv,
            wrapped_vault_key_recovery,
            wrapped_vault_key_recovery_iv
        )
        VALUES (
            :user_id,
            :vault_salt,
            :vault_iterations,
            :vault_key_check,
            :wrapped_vault_key,
            :wrapped_vault_key_iv,
            :wrapped_vault_key_recovery,
            :wrapped_vault_key_recovery_iv
        )
        ON CONFLICT (user_id)
        DO UPDATE SET
            vault_salt = EXCLUDED.vault_salt,
            vault_iterations = EXCLUDED.vault_iterations,
            vault_key_check = EXCLUDED.vault_key_check,
            wrapped_vault_key = EXCLUDED.wrapped_vault_key,
            wrapped_vault_key_iv = EXCLUDED.wrapped_vault_key_iv,
            wrapped_vault_key_recovery = EXCLUDED.wrapped_vault_key_recovery,
            wrapped_vault_key_recovery_iv = EXCLUDED.wrapped_vault_key_recovery_iv,
            updated_at = NOW()
    ');

    $stmt->execute([
        'user_id' => $userId,
        'vault_salt' => $vaultSalt,
        'vault_iterations' => $vaultIterations,
        'vault_key_check' => $vaultKeyCheck,
        'wrapped_vault_key' => $wrappedVaultKey,
        'wrapped_vault_key_iv' => $wrappedVaultKeyIv,
        'wrapped_vault_key_recovery' => $wrappedVaultKeyRecovery,
        'wrapped_vault_key_recovery_iv' => $wrappedVaultKeyRecoveryIv
    ]);

    if ($plainRecoveryKey !== "") {
        $saved = upsertRecoveryKey($pdo, $userId, $plainRecoveryKey);

        if (!$saved) {
            throw new Exception("Could not sync account recovery key.");
        }
    }

    $pdo->commit();

    echo json_encode([
        "ok" => true
    ]);
} catch (Throwable $e) {
    if ($pdo->inTransaction()) {
        $pdo->rollBack();
    }

    http_response_code(500);
    echo json_encode([
        "ok" => false,
        "error" => "Could not initialize vault profile.",
        "debug" => $e->getMessage()
    ]);
}
