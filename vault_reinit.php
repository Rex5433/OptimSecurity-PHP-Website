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

$userId = (int) $_SESSION["user_id"];

try {
    $pdo->beginTransaction();

    // Delete old vault items for this user
    $deleteItemsStmt = $pdo->prepare('
        DELETE FROM public.vault
        WHERE userid = :user_id
    ');
    $deleteItemsStmt->execute([
        'user_id' => $userId
    ]);

    // Reset or create vault profile
    $profileCheckStmt = $pdo->prepare('
        SELECT user_id
        FROM public.vault_profile
        WHERE user_id = :user_id
        LIMIT 1
    ');
    $profileCheckStmt->execute([
        'user_id' => $userId
    ]);

    $profileExists = $profileCheckStmt->fetch(PDO::FETCH_ASSOC);

    if ($profileExists) {
        $resetProfileStmt = $pdo->prepare('
            UPDATE public.vault_profile
            SET
                vault_state = :vault_state,
                vault_reset_at = NULL,
                vault_salt = NULL,
                vault_iterations = NULL,
                vault_key_check = NULL,
                wrapped_vault_key = NULL,
                wrapped_vault_key_iv = NULL,
                wrapped_vault_key_recovery = NULL,
                wrapped_vault_key_recovery_iv = NULL
            WHERE user_id = :user_id
        ');
        $resetProfileStmt->execute([
            'vault_state' => 'active',
            'user_id' => $userId
        ]);
    } else {
        $insertProfileStmt = $pdo->prepare('
            INSERT INTO public.vault_profile (
                user_id,
                vault_state,
                vault_reset_at,
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
                :vault_state,
                NULL,
                NULL,
                NULL,
                NULL,
                NULL,
                NULL,
                NULL,
                NULL
            )
        ');
        $insertProfileStmt->execute([
            'user_id' => $userId,
            'vault_state' => 'active'
        ]);
    }

    $pdo->commit();

    echo json_encode([
        "ok" => true
    ]);
    exit;
} catch (Throwable $e) {
    if ($pdo->inTransaction()) {
        $pdo->rollBack();
    }

    http_response_code(500);
    echo json_encode([
        "ok" => false,
        "error" => "Could not create a new vault."
    ]);
    exit;
}
