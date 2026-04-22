<?php

require_once __DIR__ . "/db.php";

function getClientIp(): string
{
    $keys = [
        "HTTP_CF_CONNECTING_IP",
        "HTTP_X_FORWARDED_FOR",
        "HTTP_X_REAL_IP",
        "REMOTE_ADDR"
    ];

    foreach ($keys as $key) {
        if (!empty($_SERVER[$key])) {
            $value = trim((string) $_SERVER[$key]);

            if ($key === "HTTP_X_FORWARDED_FOR" && str_contains($value, ",")) {
                $parts = explode(",", $value);
                $value = trim((string) ($parts[0] ?? ""));
            }

            if ($value !== "") {
                return $value;
            }
        }
    }

    return "unknown";
}

function getUserAgentText(): string
{
    return trim((string) ($_SERVER["HTTP_USER_AGENT"] ?? "unknown"));
}

function getDeviceFingerprint(): string
{
    return hash("sha256", getClientIp() . "|" . getUserAgentText());
}

function logAttackEvent(
    string $type,
    string $severity = "low",
    string $source = "system",
    array $details = []
): void {
    global $pdo;

    if (!($pdo instanceof PDO)) {
        error_log("logAttackEvent skipped: PDO unavailable");
        return;
    }

    $userId = null;

    if (isset($details["userId"]) && is_numeric($details["userId"])) {
        $userId = (int) $details["userId"];
    } elseif (isset($_SESSION["user_id"]) && is_numeric($_SESSION["user_id"])) {
        $userId = (int) $_SESSION["user_id"];
    }

    $location = isset($details["location"]) ? trim((string) $details["location"]) : null;
    $city = isset($details["city"]) ? trim((string) $details["city"]) : null;
    $region = isset($details["region"]) ? trim((string) $details["region"]) : null;
    $country = isset($details["country"]) ? trim((string) $details["country"]) : null;

    $location = $location !== "" ? $location : null;
    $city = $city !== "" ? $city : null;
    $region = $region !== "" ? $region : null;
    $country = $country !== "" ? $country : null;

    try {
        $stmt = $pdo->prepare("
            INSERT INTO public.login_activity
            (
                user_id,
                created_at,
                event_type,
                ip_address,
                location,
                city,
                region,
                country,
                user_agent
            )
            VALUES
            (
                :user_id,
                NOW(),
                :event_type,
                :ip_address,
                :location,
                :city,
                :region,
                :country,
                :user_agent
            )
        ");

        $stmt->bindValue(":user_id", $userId, $userId === null ? PDO::PARAM_NULL : PDO::PARAM_INT);
        $stmt->bindValue(":event_type", trim($type) !== "" ? trim($type) : "unknown_event", PDO::PARAM_STR);
        $stmt->bindValue(":ip_address", getClientIp(), PDO::PARAM_STR);
        $stmt->bindValue(":location", $location, $location !== null ? PDO::PARAM_STR : PDO::PARAM_NULL);
        $stmt->bindValue(":city", $city, $city !== null ? PDO::PARAM_STR : PDO::PARAM_NULL);
        $stmt->bindValue(":region", $region, $region !== null ? PDO::PARAM_STR : PDO::PARAM_NULL);
        $stmt->bindValue(":country", $country, $country !== null ? PDO::PARAM_STR : PDO::PARAM_NULL);
        $stmt->bindValue(":user_agent", getUserAgentText(), PDO::PARAM_STR);

        $stmt->execute();
    } catch (Throwable $e) {
        error_log("logAttackEvent DB insert failed: " . $e->getMessage());
    }
}

function trackUserDevice(int $userId, string $userName = "User"): bool
{
    global $pdo;

    if (!($pdo instanceof PDO)) {
        error_log("trackUserDevice skipped: PDO unavailable");
        return false;
    }

    $fingerprint = getDeviceFingerprint();
    $ip = getClientIp();
    $userAgent = getUserAgentText();

    try {
        $check = $pdo->prepare("
            SELECT id
            FROM public.user_devices
            WHERE user_id = :user_id
              AND fingerprint = :fingerprint
            LIMIT 1
        ");
        $check->execute([
            "user_id" => $userId,
            "fingerprint" => $fingerprint
        ]);

        $existingId = $check->fetchColumn();
        $isNewDevice = ($existingId === false);

        if ($isNewDevice) {
            $insert = $pdo->prepare("
                INSERT INTO public.user_devices
                (
                    user_id,
                    user_name,
                    fingerprint,
                    ip_address,
                    user_agent,
                    first_seen,
                    last_seen
                )
                VALUES
                (
                    :user_id,
                    :user_name,
                    :fingerprint,
                    :ip_address,
                    :user_agent,
                    NOW(),
                    NOW()
                )
            ");
            $insert->execute([
                "user_id" => $userId,
                "user_name" => $userName,
                "fingerprint" => $fingerprint,
                "ip_address" => $ip,
                "user_agent" => $userAgent
            ]);
        } else {
            $update = $pdo->prepare("
                UPDATE public.user_devices
                SET
                    user_name = :user_name,
                    ip_address = :ip_address,
                    user_agent = :user_agent,
                    last_seen = NOW()
                WHERE id = :id
            ");
            $update->execute([
                "id" => $existingId,
                "user_name" => $userName,
                "ip_address" => $ip,
                "user_agent" => $userAgent
            ]);
        }

        return $isNewDevice;
    } catch (Throwable $e) {
        error_log("trackUserDevice DB error: " . $e->getMessage());
        return false;
    }
}

if (!function_exists("formatAttackType")) {
    function formatAttackType(string $type): string
    {
        return match ($type) {
            "phishing_detected" => "Phishing Detected",
            "password_attack" => "Password Attack",
            "failed_login" => "Failed Login",
            "failed_login_form_error" => "Login Form Error",
            "successful_login" => "Successful Login",
            "password_verified_2fa_pending" => "2FA Verification Pending",
            "new_device_login" => "New Device Login",
            "suspicious_request" => "Suspicious Request",
            "blocked_ip" => "Blocked IP",
            "malicious_url" => "Malicious URL",
            "model_detection" => "Model Detection",
            default => "Unknown Activity",
        };
    }
}
