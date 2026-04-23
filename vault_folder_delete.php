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
    $pdo->beginTransaction();

    $deleteFolder = $pdo->prepare('
        DELETE FROM public.vault_folders
        WHERE user_id = :user_id
          AND folder_name = :folder_name
    ');
    $deleteFolder->execute([
        'user_id' => (int) $_SESSION["user_id"],
        'folder_name' => $folderName
    ]);

    $clearItems = $pdo->prepare('
        UPDATE public.vault_items
        SET folder_name = '',
            updated_at = NOW()
        WHERE user_id = :user_id
          AND folder_name = :folder_name
    ');
    $clearItems->execute([
        'user_id' => (int) $_SESSION["user_id"],
        'folder_name' => $folderName
    ]);

    $pdo->commit();

    echo json_encode(["ok" => true]);
} catch (Throwable $e) {
    if ($pdo->inTransaction()) {
        $pdo->rollBack();
    }

    http_response_code(500);
    echo json_encode([
        "ok" => false,
        "error" => "Could not delete folder.",
        "debug" => $e->getMessage()
    ]);
}
