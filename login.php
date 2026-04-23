<?php
session_start();

header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Cache-Control: post-check=0, pre-check=0", false);
header("Pragma: no-cache");
header("Expires: 0");

if (isset($_SESSION["user_id"])) {
    header("Location: homepage.php");
    exit;
}

include "db.php";
require_once __DIR__ . "/attack_helpers.php";

$message = "";

if (isset($_GET["created"]) && $_GET["created"] === "1") {
    $message = "Account created successfully. You can now log in.";
}

/*
|--------------------------------------------------------------------------
| Clear stale pending 2FA session values on fresh login page load
|--------------------------------------------------------------------------
*/
if ($_SERVER["REQUEST_METHOD"] !== "POST") {
    unset(
        $_SESSION["pending_2fa_user_id"],
        $_SESSION["pending_2fa_name"],
        $_SESSION["pending_2fa_username"],
        $_SESSION["pending_2fa_verified_at"]
    );
}

function getClientIpAddress(): string
{
    $candidates = [
        $_SERVER["HTTP_CF_CONNECTING_IP"] ?? "",
        $_SERVER["HTTP_X_REAL_IP"] ?? "",
        $_SERVER["HTTP_X_FORWARDED_FOR"] ?? "",
        $_SERVER["REMOTE_ADDR"] ?? ""
    ];

    foreach ($candidates as $candidate) {
        $candidate = trim((string) $candidate);
        if ($candidate === "") {
            continue;
        }

        if (str_contains($candidate, ",")) {
            $parts = explode(",", $candidate);
            $candidate = trim((string) ($parts[0] ?? ""));
        }

        if (filter_var($candidate, FILTER_VALIDATE_IP)) {
            return $candidate;
        }
    }

    return "";
}

function fetchGeoDataForIp(string $ipAddress): array
{
    $empty = [
        "location" => "",
        "city" => "",
        "region" => "",
        "country" => ""
    ];

    $ipAddress = trim($ipAddress);
    if ($ipAddress === "") {
        return $empty;
    }

    if ($ipAddress === "::1" || $ipAddress === "127.0.0.1") {
        return [
            "location" => "Localhost",
            "city" => "Localhost",
            "region" => "Localhost",
            "country" => "Localhost"
        ];
    }

    if (
        filter_var($ipAddress, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false
    ) {
        return [
            "location" => "Private Network",
            "city" => "",
            "region" => "",
            "country" => ""
        ];
    }

    $url = "http://ip-api.com/json/" . rawurlencode($ipAddress) . "?fields=status,message,country,regionName,city,query";
    $context = stream_context_create([
        "http" => [
            "method" => "GET",
            "timeout" => 4,
            "header" => "User-Agent: Optimsecurity/1.0\r\n"
        ]
    ]);

    $raw = @file_get_contents($url, false, $context);
    if ($raw === false) {
        return $empty;
    }

    $data = json_decode($raw, true);
    if (!is_array($data) || ($data["status"] ?? "") !== "success") {
        return $empty;
    }

    $city = trim((string) ($data["city"] ?? ""));
    $region = trim((string) ($data["regionName"] ?? ""));
    $country = trim((string) ($data["country"] ?? ""));

    $locationParts = array_values(array_filter([$city, $region, $country], function ($value) {
        return trim((string) $value) !== "";
    }));

    return [
        "location" => !empty($locationParts) ? implode(", ", $locationParts) : "",
        "city" => $city,
        "region" => $region,
        "country" => $country
    ];
}

function enrichLatestLoginActivity(PDO $pdo, ?int $userId, string $eventType): void
{
    if (!$pdo || !$userId || $userId <= 0) {
        return;
    }

    $eventType = trim($eventType);
    if ($eventType === "") {
        return;
    }

    $ipAddress = getClientIpAddress();
    $geo = fetchGeoDataForIp($ipAddress);

    try {
        $stmt = $pdo->prepare("
            UPDATE public.login_activity
            SET
                ip_address = COALESCE(NULLIF(ip_address, ''), :ip_address),
                location = COALESCE(NULLIF(location, ''), :location),
                city = COALESCE(NULLIF(city, ''), :city),
                region = COALESCE(NULLIF(region, ''), :region),
                country = COALESCE(NULLIF(country, ''), :country)
            WHERE id = (
                SELECT id
                FROM public.login_activity
                WHERE user_id = :user_id
                  AND LOWER(TRIM(COALESCE(event_type, ''))) = :event_type
                ORDER BY created_at DESC
                LIMIT 1
            )
        ");

        $stmt->execute([
            "ip_address" => $ipAddress,
            "location" => $geo["location"],
            "city" => $geo["city"],
            "region" => $geo["region"],
            "country" => $geo["country"],
            "user_id" => $userId,
            "event_type" => strtolower($eventType)
        ]);
    } catch (Throwable $e) {
        // Fail silently so login is never blocked by enrichment
    }
}

function finalizeLogin(array $user_row): void
{
    global $pdo;

    session_regenerate_id(true);

    unset(
        $_SESSION["pending_2fa_user_id"],
        $_SESSION["pending_2fa_name"],
        $_SESSION["pending_2fa_username"],
        $_SESSION["pending_2fa_verified_at"]
    );

    $_SESSION["user_id"] = $user_row["id"];
    $_SESSION["user_name"] = $user_row["name"];
    $_SESSION["user_username"] = $user_row["username"];
    $_SESSION["logged_in"] = true;

    logAttackEvent(
        "successful_login",
        "low",
        "login.php",
        [
            "userId" => $user_row["id"],
            "username" => $user_row["username"]
        ]
    );

    if ($pdo instanceof PDO) {
        enrichLatestLoginActivity($pdo, (int) $user_row["id"], "successful_login");
    }

    $displayName = trim((string) ($user_row["name"] ?? ""));
    if ($displayName === "") {
        $displayName = (string) $user_row["username"];
    }

    if (function_exists("trackUserDevice")) {
        $isNewDevice = trackUserDevice((int) $user_row["id"], $displayName);

        if ($isNewDevice) {
            logAttackEvent(
                "new_device_login",
                "high",
                "login.php",
                [
                    "userId" => $user_row["id"],
                    "username" => $user_row["username"]
                ]
            );

            if ($pdo instanceof PDO) {
                enrichLatestLoginActivity($pdo, (int) $user_row["id"], "new_device_login");
            }
        }
    }

    header("Location: homepage.php");
    exit;
}

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $username = trim($_POST["username"] ?? "");
    $password_input = $_POST["password"] ?? "";

    if ($username === "" || $password_input === "") {
        $message = "Please fill in all fields.";

        logAttackEvent(
            "failed_login_form_error",
            "medium",
            "login.php",
            [
                "username" => $username,
                "reason" => "Missing login fields"
            ]
        );
    } elseif (!$pdo) {
        $message = "Database connection failed.";

        logAttackEvent(
            "suspicious_request",
            "medium",
            "login.php",
            [
                "username" => $username,
                "reason" => "Database connection failed during login"
            ]
        );
    } else {
        $stmt = $pdo->prepare('SELECT * FROM "Accounts" WHERE username = :username LIMIT 1');
        $stmt->execute(["username" => $username]);
        $user_row = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user_row && password_verify($password_input, (string) $user_row["password"])) {
            $twofaRaw = $user_row["twofa_enabled"] ?? false;
            $twofaSecret = trim((string) ($user_row["twofa_secret"] ?? ""));

            $twofaFlag = (
                $twofaRaw === true ||
                $twofaRaw === 1 ||
                $twofaRaw === "1" ||
                $twofaRaw === "t" ||
                $twofaRaw === "true"
            );

            $twofaEnabled = $twofaFlag && $twofaSecret !== "";

            if ($twofaEnabled) {
                session_regenerate_id(true);

                unset(
                    $_SESSION["user_id"],
                    $_SESSION["user_name"],
                    $_SESSION["user_username"],
                    $_SESSION["logged_in"]
                );

                $_SESSION["pending_2fa_user_id"] = $user_row["id"];
                $_SESSION["pending_2fa_name"] = $user_row["name"];
                $_SESSION["pending_2fa_username"] = $user_row["username"];
                $_SESSION["pending_2fa_verified_at"] = time();

                logAttackEvent(
                    "password_verified_2fa_pending",
                    "medium",
                    "login.php",
                    [
                        "userId" => $user_row["id"],
                        "username" => $user_row["username"]
                    ]
                );

                if ($pdo instanceof PDO) {
                    enrichLatestLoginActivity($pdo, (int) $user_row["id"], "password_verified_2fa_pending");
                }

                header("Location: verify_2fa.php");
                exit;
            }

            finalizeLogin($user_row);
        } else {
            $message = "Invalid username or password.";

            $failedUserId = null;

            if ($user_row && isset($user_row["id"]) && is_numeric($user_row["id"])) {
                $failedUserId = (int) $user_row["id"];
            }

            logAttackEvent(
                "failed_login",
                "high",
                "login.php",
                [
                    "userId" => $failedUserId,
                    "username" => $username,
                    "reason" => "Invalid username or password"
                ]
            );

            if ($pdo instanceof PDO && $failedUserId !== null) {
                enrichLatestLoginActivity($pdo, $failedUserId, "failed_login");
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login | Optimsecurity</title>
    <link rel="stylesheet" href="styles.css">
    <link rel="icon" href="/favicon.ico" type="image/x-icon">

    <link rel="icon" type="image/png" sizes="32x32" href="/favicon-32x32.png">
    <link rel="icon" type="image/png" sizes="16x16" href="/favicon-16x16.png">

    <link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png">
    <link rel="manifest" href="/site.webmanifest">
</head>
<body>

<div class="login-wrapper">
    <div class="login-box">

        <div class="login-logo">
            <img src="optimsecuritylogo.png" alt="Optimsecurity Logo">
        </div>

        <h1>Login</h1>

        <?php if ($message): ?>
            <div class="<?= (isset($_GET["created"]) && $_GET["created"] === "1") ? 'login-success' : 'login-error' ?>">
                <?= htmlspecialchars($message) ?>
            </div>
        <?php endif; ?>

        <form method="post" action="" id="loginForm" novalidate>
            <div class="form-group">
                <label for="username">Username</label>
                <input
                    type="text"
                    id="username"
                    name="username"
                    placeholder="Enter username"
                    value="<?= htmlspecialchars($_POST["username"] ?? "") ?>"
                    autocomplete="username"
                    required
                >
            </div>

            <div class="form-group">
                <label for="password">Password</label>
                <input
                    type="password"
                    id="password"
                    name="password"
                    placeholder="Enter password"
                    autocomplete="current-password"
                    required
                >
            </div>

            <div class="options-row">
                <label class="checkbox-container" for="show-password">
                    <input type="checkbox" id="show-password">
                    <span>Show Password</span>
                </label>

                <a href="forgot_password.php" class="forgot-link">Forgot password?</a>
            </div>

            <button type="submit" class="login-submit">Login</button>
        </form>

        <div class="divider"></div>

        <p class="bottom-link">
            <a href="create_user.php">Create Account</a>
        </p>
    </div>
</div>

<script>
(function () {
    const form = document.getElementById("loginForm");
    const passwordInput = document.getElementById("password");
    const showPasswordCheckbox = document.getElementById("show-password");

    function togglePassword() {
        if (!passwordInput) {
            return;
        }
        passwordInput.type = passwordInput.type === "password" ? "text" : "password";
    }

    if (showPasswordCheckbox) {
        showPasswordCheckbox.addEventListener("change", togglePassword);
    }

    if (form && passwordInput) {
        form.addEventListener("submit", function () {
            try {
                sessionStorage.setItem("vault_login_password", passwordInput.value || "");
            } catch (e) {
                // Ignore storage issues silently
            }
        });
    }

    window.togglePassword = togglePassword;
})();
</script>

</body>
</html>
