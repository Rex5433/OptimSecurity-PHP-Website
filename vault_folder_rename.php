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
$oldName = trim((string) ($body["old_name"] ?? ""));
$newName = trim((string) ($body["new_name"] ?? ""));

if ($oldName === "" || $newName === "") {
    http_response_code(400);
    echo json_encode(["ok" => false, "error" => "Old and new folder names are required."]);
    exit;
}

try {
    $pdo->beginTransaction();

    $renameFolder = $pdo->prepare('
        UPDATE public.vault_folders
        SET folder_name = :new_name,
            updated_at = NOW()
        WHERE user_id = :user_id
          AND folder_name = :old_name
    ');
    $renameFolder->execute([
        'user_id' => (int) $_SESSION["user_id"],
        'old_name' => $oldName,
        'new_name' => $newName
    ]);

    $renameItems = $pdo->prepare('
        UPDATE public.vault_items
        SET folder_name = :new_name,
            updated_at = NOW()
        WHERE user_id = :user_id
          AND folder_name = :old_name
    ');
    $renameItems->execute([
        'user_id' => (int) $_SESSION["user_id"],
        'old_name' => $oldName,
        'new_name' => $newName
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
        "error" => "Could not rename folder.",
        "debug" => $e->getMessage()
    ]);
}
