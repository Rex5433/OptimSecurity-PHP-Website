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

require_once "db.php";

if (!$pdo) {
    http_response_code(500);
    echo json_encode([
        "ok" => false,
        "error" => "Database connection failed."
    ]);
    exit;
}

try {
    $stmt = $pdo->prepare('
        SELECT
            user_id,
            vault_salt,
            vault_iterations,
            vault_key_check,
            wrapped_vault_key,
            wrapped_vault_key_iv
        FROM public.vault_profile
        WHERE user_id = :user_id
        LIMIT 1
    ');
    $stmt->execute([
        'user_id' => (int) $_SESSION["user_id"]
    ]);

    $profile = $stmt->fetch(PDO::FETCH_ASSOC);

    echo json_encode([
        "ok" => true,
        "exists" => (bool) $profile,
        "profile" => $profile ?: null
    ]);
} catch (Throwable $e) {
    http_response_code(500);
    echo json_encode([
        "ok" => false,
        "error" => "Could not load vault profile.",
        "debug" => $e->getMessage()
    ]);
}