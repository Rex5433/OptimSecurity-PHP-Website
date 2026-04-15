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

include "db.php";

if (!$pdo) {
    http_response_code(500);
    echo json_encode([
        "ok" => false,
        "error" => "Database connection failed."
    ]);
    exit;
}

$body = json_decode(file_get_contents("php://input"), true);

$wrappedVaultKey = trim((string) ($body["wrapped_vault_key"] ?? ""));
$wrappedVaultKeyIv = trim((string) ($body["wrapped_vault_key_iv"] ?? ""));

if ($wrappedVaultKey === "" || $wrappedVaultKeyIv === "") {
    http_response_code(400);
    echo json_encode([
        "ok" => false,
        "error" => "Missing wrapped vault key fields."
    ]);
    exit;
}

try {
    $update = $pdo->prepare('
        UPDATE public.vault_profile
        SET wrapped_vault_key = :wrapped_vault_key,
            wrapped_vault_key_iv = :wrapped_vault_key_iv,
            updated_at = NOW()
        WHERE user_id = :user_id
    ');
    $update->execute([
        'wrapped_vault_key' => $wrappedVaultKey,
        'wrapped_vault_key_iv' => $wrappedVaultKeyIv,
        'user_id' => (int) $_SESSION["user_id"]
    ]);

    echo json_encode([
        "ok" => true
    ]);
} catch (Throwable $e) {
    http_response_code(500);
    echo json_encode([
        "ok" => false,
        "error" => "Could not rewrap vault key."
    ]);
}