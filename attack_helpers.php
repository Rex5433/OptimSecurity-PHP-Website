<?php

function attackFilePath(): string
{
    return __DIR__ . "/attack_events.json";
}

function userDevicesFilePath(): string
{
    return __DIR__ . "/user_devices.json";
}

function ensureJsonFile(string $file, string $default = "[]"): void
{
    if (!file_exists($file)) {
        file_put_contents($file, $default, LOCK_EX);
    }
}

function readJsonArrayFile(string $file): array
{
    ensureJsonFile($file, "[]");

    $raw = file_get_contents($file);
    $data = json_decode($raw, true);

    return is_array($data) ? $data : [];
}

function readJsonObjectFile(string $file): array
{
    ensureJsonFile($file, "{}");

    $raw = file_get_contents($file);
    $data = json_decode($raw, true);

    return is_array($data) ? $data : [];
}

function writeJsonFile(string $file, array $data): bool
{
    return file_put_contents(
        $file,
        json_encode($data, JSON_PRETTY_PRINT),
        LOCK_EX
    ) !== false;
}

function getClientIp(): string
{
    if (!empty($_SERVER["HTTP_X_FORWARDED_FOR"])) {
        $parts = explode(",", $_SERVER["HTTP_X_FORWARDED_FOR"]);
        return trim($parts[0]);
    }

    return $_SERVER["REMOTE_ADDR"] ?? "unknown";
}

function getUserAgentText(): string
{
    return $_SERVER["HTTP_USER_AGENT"] ?? "unknown";
}

function getDeviceFingerprint(): string
{
    $ip = getClientIp();
    $ua = getUserAgentText();

    return hash("sha256", $ip . "|" . $ua);
}

function cleanOldAttackEvents(array $events, int $max = 300): array
{
    usort($events, function ($a, $b) {
        return strtotime($b["timestamp"] ?? "") <=> strtotime($a["timestamp"] ?? "");
    });

    return array_slice($events, 0, $max);
}

function logAttackEvent(
    string $type,
    string $severity = "low",
    string $source = "system",
    array $details = []
): void {
    $file = attackFilePath();
    $events = readJsonArrayFile($file);

    $events[] = [
        "timestamp" => date("c"),
        "type" => $type,
        "severity" => strtolower(trim($severity)),
        "source" => $source,
        "ip" => getClientIp(),
        "userAgent" => getUserAgentText(),
        "details" => $details
    ];

    $events = cleanOldAttackEvents($events, 300);
    writeJsonFile($file, $events);
}

function trackUserDevice(int $userId, string $userName = "User"): bool
{
    $file = userDevicesFilePath();
    $devices = readJsonObjectFile($file);

    $userKey = (string) $userId;
    $fingerprint = getDeviceFingerprint();

    if (!isset($devices[$userKey]) || !is_array($devices[$userKey])) {
        $devices[$userKey] = [];
    }

    $isNewDevice = !isset($devices[$userKey][$fingerprint]);

    $devices[$userKey][$fingerprint] = [
        "lastSeen" => date("c"),
        "ip" => getClientIp(),
        "userAgent" => getUserAgentText(),
        "userName" => $userName
    ];

    writeJsonFile($file, $devices);

    return $isNewDevice;
}

if (!function_exists("formatAttackType")) {
    function formatAttackType(string $type): string
    {
        return match ($type) {
            "phishing_detected" => "Phishing Detected",
            "password_attack" => "Password Attack",
            "failed_login" => "Failed Login",
            "successful_login" => "Successful Login",
            "new_device_login" => "New Device Login",
            "suspicious_request" => "Suspicious Request",
            "blocked_ip" => "Blocked IP",
            "malicious_url" => "Malicious URL",
            "model_detection" => "Model Detection",
            default => "Unknown Activity",
        };
    }
}