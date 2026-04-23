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
$folderName = trim((string) ($body["folder_name"] ?? ""));
$userId = (int) $_SESSION["user_id"];

if ($folderName === "") {
    http_response_code(400);
    echo json_encode([
        "ok" => false,
        "error" => "Folder name is required."
    ]);
    exit;
}

try {
    $checkStmt = $pdo->prepare("
        SELECT id
        FROM public.vault_folders
        WHERE user_id = :user_id
          AND folder_name = :folder_name
        LIMIT 1
    ");
    $checkStmt->execute([
        "user_id" => $userId,
        "folder_name" => $folderName
    ]);

    $existing = $checkStmt->fetch(PDO::FETCH_ASSOC);

    if (!$existing) {
        $insertStmt = $pdo->prepare("
            INSERT INTO public.vault_folders (
                user_id,
                folder_name,
                created_at,
                updated_at
            )
            VALUES (
                :user_id,
                :folder_name,
                NOW(),
                NOW()
            )
        ");
        $insertStmt->execute([
            "user_id" => $userId,
            "folder_name" => $folderName
        ]);
    }

    echo json_encode([
        "ok" => true
    ]);
    exit;
} catch (Throwable $e) {
    http_response_code(500);
    echo json_encode([
        "ok" => false,
        "error" => "Could not save folder.",
        "debug" => $e->getMessage()
    ]);
    exit;
}
