<?php
session_start();
header("Content-Type: application/json");

if (!isset($_SESSION["user_id"])) {
    http_response_code(401);
    echo json_encode(["ok" => false, "error" => "Not logged in."]);
    exit;
}

require_once "db.php";

if (!$pdo) {
    http_response_code(500);
    echo json_encode(["ok" => false, "error" => "Database connection failed."]);
    exit;
}

try {
    $stmt = $pdo->prepare('
        SELECT id, folder_name
        FROM public.vault_folders
        WHERE user_id = :user_id
        ORDER BY folder_name ASC
    ');
    $stmt->execute([
        'user_id' => (int) $_SESSION["user_id"]
    ]);

    echo json_encode([
        "ok" => true,
        "folders" => $stmt->fetchAll(PDO::FETCH_ASSOC)
    ]);
} catch (Throwable $e) {
    http_response_code(500);
    echo json_encode([
        "ok" => false,
        "error" => "Could not load folders.",
        "debug" => $e->getMessage()
    ]);
}
