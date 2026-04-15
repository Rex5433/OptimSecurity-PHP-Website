<?php
declare(strict_types=1);

session_start();

require_once __DIR__ . "/config.php";
require_once __DIR__ . "/fastapi_auth.php";

header("Content-Type: application/json");

if (!isset($_SESSION["user_id"])) {
    http_response_code(401);
    echo json_encode([
        "detail" => "Not authenticated."
    ]);
    exit;
}

if ($_SERVER["REQUEST_METHOD"] !== "POST") {
    http_response_code(405);
    echo json_encode([
        "detail" => "Method not allowed."
    ]);
    exit;
}

if ($fastApiBaseUrl === "") {
    http_response_code(500);
    echo json_encode([
        "detail" => "FastAPI service URL is not configured."
    ]);
    exit;
}

$rawInput = file_get_contents("php://input");
$endpoint = rtrim($fastApiBaseUrl, "/") . "/generate-passwords";

try {
    $idToken = getCloudRunIdToken($fastApiBaseUrl);

    $ch = curl_init($endpoint);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        "Content-Type: application/json",
        "Authorization: Bearer " . $idToken
    ]);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $rawInput);
    curl_setopt($ch, CURLOPT_TIMEOUT, 120);

    $response = curl_exec($ch);

    if (curl_errno($ch)) {
        $error = curl_error($ch);
        curl_close($ch);

        error_log("Generator proxy connection error: " . $error);

        http_response_code(500);
        echo json_encode([
            "detail" => "Password generation service is unavailable."
        ]);
        exit;
    }

    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    http_response_code($httpCode);
    echo $response;
} catch (Throwable $e) {
    error_log("Generator proxy error: " . $e->getMessage());

    http_response_code(500);
    echo json_encode([
        "detail" => "Password generation service is unavailable."
    ]);
}
?>
