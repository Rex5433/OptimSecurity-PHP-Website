<?php

function logAttackEvent(string $type, string $severity = "medium", string $source = "dashboard", string $details = ""): bool
{
    $file = __DIR__ . "/attack_events.json";

    $allowedTypes = [
        "phishing_detected",
        "password_attack",
        "failed_login",
        "suspicious_request",
        "blocked_ip",
        "malicious_url",
        "model_detection"
    ];

    $allowedSeverities = ["low", "medium", "high", "critical"];

    if (!in_array($type, $allowedTypes, true)) {
        return false;
    }

    if (!in_array($severity, $allowedSeverities, true)) {
        $severity = "medium";
    }

    if (!file_exists($file)) {
        file_put_contents($file, "[]");
    }

    $json = file_get_contents($file);
    $events = json_decode($json, true);

    if (!is_array($events)) {
        $events = [];
    }

    $events[] = [
        "timestamp" => date("c"),
        "type" => $type,
        "severity" => $severity,
        "source" => $source,
        "details" => $details
    ];

    if (count($events) > 500) {
        $events = array_slice($events, -500);
    }

    return file_put_contents($file, json_encode($events, JSON_PRETTY_PRINT)) !== false;
}