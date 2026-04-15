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
$itemId = isset($body["item_id"]) ? (int) $body["item_id"] : 0;

$itemName = trim((string) ($body["item_name"] ?? ""));
$itemType = trim((string) ($body["item_type"] ?? ""));
$folderName = trim((string) ($body["folder_name"] ?? ""));
$encryptedData = trim((string) ($body["encrypted_data"] ?? ""));
$iv = trim((string) ($body["iv"] ?? ""));

if ($itemName === "" || $itemType === "" || $encryptedData === "" || $iv === "") {
    http_response_code(400);
    echo json_encode([
        "ok" => false,
        "error" => "Missing required vault fields.",
        "debug" => [
            "item_name_present" => $itemName !== "",
            "item_type_present" => $itemType !== "",
            "encrypted_data_present" => $encryptedData !== "",
            "iv_present" => $iv !== ""
        ]
    ]);
    exit;
}

try {
    if ($itemId > 0) {
        $stmt = $pdo->prepare('
            UPDATE public.vault_item
            SET item_name = :item_name,
                item_type = :item_type,
                folder_name = :folder_name,
                encrypted_data = :encrypted_data,
                iv = :iv,
                updated_at = NOW()
            WHERE id = :id
              AND user_id = :user_id
        ');
        $stmt->execute([
            ':item_name' => $itemName,
            ':item_type' => $itemType,
            ':folder_name' => ($folderName === "" ? null : $folderName),
            ':encrypted_data' => $encryptedData,
            ':iv' => $iv,
            ':id' => $itemId,
            ':user_id' => $userId
        ]);
    } else {
        $stmt = $pdo->prepare('
            INSERT INTO public.vault_item (
                user_id,
                item_name,
                item_type,
                folder_name,
                encrypted_data,
                iv,
                created_at,
                updated_at
            )
            VALUES (
                :user_id,
                :item_name,
                :item_type,
                :folder_name,
                :encrypted_data,
                :iv,
                NOW(),
                NOW()
            )
            RETURNING id
        ');
        $stmt->execute([
            ':user_id' => $userId,
            ':item_name' => $itemName,
            ':item_type' => $itemType,
            ':folder_name' => ($folderName === "" ? null : $folderName),
            ':encrypted_data' => $encryptedData,
            ':iv' => $iv
        ]);

        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        $itemId = (int) ($row["id"] ?? 0);
    }

    echo json_encode([
        "ok" => true,
        "item_id" => $itemId
    ]);
} catch (Throwable $e) {
    http_response_code(500);
    echo json_encode([
        "ok" => false,
        "error" => $e->getMessage()
    ]);
}