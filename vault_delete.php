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
$itemId = isset($body["item_id"]) ? (int) $body["item_id"] : 0;

if ($itemId <= 0) {
    http_response_code(400);
    echo json_encode([
        "ok" => false,
        "error" => "Invalid item ID."
    ]);
    exit;
}

try {
    $stmt = $pdo->prepare('
        DELETE FROM public.vault_item
        WHERE id = :id AND user_id = :user_id
    ');
    $stmt->execute([
        'id' => $itemId,
        'user_id' => (int) $_SESSION["user_id"]
    ]);

    echo json_encode([
        "ok" => true
    ]);
} catch (Throwable $e) {
    http_response_code(500);
    echo json_encode([
        "ok" => false,
        "error" => "Could not delete vault item.",
        "debug" => $e->getMessage()
    ]);
}