<?php
require_once "attack_logger.php";

$types = [
    "phishing_detected",
    "password_attack",
    "failed_login",
    "suspicious_request",
    "blocked_ip",
    "malicious_url",
    "model_detection"
];

$severities = ["low", "medium", "high", "critical"];

$type = $types[array_rand($types)];
$severity = $severities[array_rand($severities)];

$success = logAttackEvent(
    $type,
    $severity,
    "test_generator",
    "Generated test event for dashboard stream."
);

echo $success ? "Test event logged." : "Failed to log event.";