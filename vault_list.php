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
    $stmt = $pdo->prepare("
        SELECT
            id,
            item_name,
            item_type,
            folder_name,
            encrypted_data,
            iv,
            created_at,
            updated_at
        FROM public.vault_items
        WHERE user_id = :user_id
        ORDER BY updated_at DESC, id DESC
    ");

    $stmt->execute([
        "user_id" => (int) $_SESSION["user_id"]
    ]);

    $items = $stmt->fetchAll(PDO::FETCH_ASSOC);

    echo json_encode([
        "ok" => true,
        "items" => $items
    ]);
} catch (Throwable $e) {
    http_response_code(500);
    echo json_encode([
        "ok" => false,
        "error" => "Could not load vault items.",
        "debug" => $e->getMessage()
    ]);
}
