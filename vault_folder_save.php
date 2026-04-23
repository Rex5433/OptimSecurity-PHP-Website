<?php
session_start();
header("Content-Type: application/json");

if (!isset($_SESSION["user_id"])) {
    http_response_code(401);
    echo json_encode(["ok" => false, "error" => "Not logged in."]);
    exit;
}

if (
    empty($_SERVER["HTTP_X_CSRF_TOKEN"]) ||
    empty($_SESSION["csrf_token"]) ||
    !hash_equals($_SESSION["csrf_token"], $_SERVER["HTTP_X_CSRF_TOKEN"])
) {
    http_response_code(403);
    echo json_encode(["ok" => false, "error" => "Invalid CSRF token."]);
    exit;
}

require_once "db.php";

if (!$pdo) {
    http_response_code(500);
    echo json_encode(["ok" => false, "error" => "Database connection failed."]);
    exit;
}

$body = json_decode(file_get_contents("php://input"), true);
$folderName = trim((string) ($body["folder_name"] ?? ""));

if ($folderName === "") {
    http_response_code(400);
    echo json_encode(["ok" => false, "error" => "Folder name is required."]);
    exit;
}

try {
    $stmt = $pdo->prepare('
        INSERT INTO public.vault_folders (user_id, folder_name, created_at, updated_at)
        VALUES (:user_id, :folder_name, NOW(), NOW())
        ON CONFLICT (user_id, folder_name)
        DO UPDATE SET updated_at = NOW()
    ');
    $stmt->execute([
        'user_id' => (int) $_SESSION["user_id"],
        'folder_name' => $folderName
    ]);

    echo json_encode(["ok" => true]);
} catch (Throwable $e) {
    http_response_code(500);
    echo json_encode([
        "ok" => false,
        "error" => "Could not save folder.",
        "debug" => $e->getMessage()
    ]);
}
