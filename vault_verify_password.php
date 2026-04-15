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

$body = json_decode(file_get_contents("php://input"), true);
$password = trim((string) ($body["password"] ?? ""));
$userId = (int) $_SESSION["user_id"];

if ($password === "") {
    http_response_code(400);
    echo json_encode([
        "ok" => false,
        "error" => "Password is required."
    ]);
    exit;
}

$stmt = $pdo->prepare('SELECT password FROM "Accounts" WHERE id = :id LIMIT 1');
$stmt->execute(["id" => $userId]);
$user = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$user) {
    http_response_code(404);
    echo json_encode([
        "ok" => false,
        "error" => "Account not found."
    ]);
    exit;
}

if (!password_verify($password, (string) $user["password"])) {
    http_response_code(401);
    echo json_encode([
        "ok" => false,
        "error" => "Incorrect website password."
    ]);
    exit;
}

echo json_encode([
    "ok" => true
]);