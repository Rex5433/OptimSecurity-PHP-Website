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
$wrappedVaultKey = trim((string) ($body["wrapped_vault_key"] ?? ""));
$wrappedVaultKeyIv = trim((string) ($body["wrapped_vault_key_iv"] ?? ""));
$wrappedVaultKeyRecovery = trim((string) ($body["wrapped_vault_key_recovery"] ?? ""));
$wrappedVaultKeyRecoveryIv = trim((string) ($body["wrapped_vault_key_recovery_iv"] ?? ""));

if (
    $wrappedVaultKey === "" ||
    $wrappedVaultKeyIv === "" ||
    $wrappedVaultKeyRecovery === "" ||
    $wrappedVaultKeyRecoveryIv === ""
) {
    http_response_code(400);
    echo json_encode([
        "ok" => false,
        "error" => "Missing rewrap fields."
    ]);
    exit;
}

try {
    $stmt = $pdo->prepare('
        UPDATE public.vault_profile
        SET wrapped_vault_key = :wrapped_vault_key,
            wrapped_vault_key_iv = :wrapped_vault_key_iv,
            wrapped_vault_key_recovery = :wrapped_vault_key_recovery,
            wrapped_vault_key_recovery_iv = :wrapped_vault_key_recovery_iv,
            updated_at = NOW()
        WHERE user_id = :user_id
    ');

    $stmt->execute([
        'wrapped_vault_key' => $wrappedVaultKey,
        'wrapped_vault_key_iv' => $wrappedVaultKeyIv,
        'wrapped_vault_key_recovery' => $wrappedVaultKeyRecovery,
        'wrapped_vault_key_recovery_iv' => $wrappedVaultKeyRecoveryIv,
        'user_id' => $userId
    ]);

    echo json_encode([
        "ok" => true
    ]);
} catch (Throwable $e) {
    http_response_code(500);
    echo json_encode([
        "ok" => false,
        "error" => "Could not rewrap vault profile after recovery.",
        "debug" => $e->getMessage()
    ]);
}
