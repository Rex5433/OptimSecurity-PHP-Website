<?php
session_start();

header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Pragma: no-cache");
header("Expires: 0");

if (isset($_SESSION["user_id"])) {
    header("Location: homepage.php");
    exit;
}

if (empty($_SESSION["pending_2fa_user_id"])) {
    header("Location: login.php");
    exit;
}

if (
    !empty($_SESSION["pending_2fa_verified_at"]) &&
    (time() - (int) $_SESSION["pending_2fa_verified_at"] > 600)
) {
    unset(
        $_SESSION["pending_2fa_user_id"],
        $_SESSION["pending_2fa_name"],
        $_SESSION["pending_2fa_username"],
        $_SESSION["pending_2fa_verified_at"]
    );
    header("Location: login.php");
    exit;
}

include "db.php";
require_once __DIR__ . "/attack_helpers.php";
require_once __DIR__ . "/twofa_helpers.php";

$message = "";
$pendingUserId = (int) $_SESSION["pending_2fa_user_id"];
$pendingUsername = (string) ($_SESSION["pending_2fa_username"] ?? "User");

if (!$pdo) {
    die("Database connection failed.");
}

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $code = strtoupper(trim($_POST["code"] ?? ""));

    if ($code === "") {
        $message = "Enter your authenticator code or backup code.";
    } else {
        $stmt = $pdo->prepare('
            SELECT *
            FROM "Accounts"
            WHERE id = :id
            LIMIT 1
        ');
        $stmt->execute(['id' => $pendingUserId]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$user) {
            $message = "Account not found.";
        } else {
            $twofaSecret = trim((string) ($user["twofa_secret"] ?? ""));
            $twofaRaw = $user["twofa_enabled"] ?? false;

            $twofaEnabled = (
                $twofaRaw === true ||
                $twofaRaw === 1 ||
                $twofaRaw === "1" ||
                $twofaRaw === "t" ||
                $twofaRaw === "true"
            );

            if (!$twofaEnabled || $twofaSecret === "") {
                unset(
                    $_SESSION["pending_2fa_user_id"],
                    $_SESSION["pending_2fa_name"],
                    $_SESSION["pending_2fa_username"],
                    $_SESSION["pending_2fa_verified_at"]
                );
                header("Location: login.php");
                exit;
            }

            $valid = false;

            if (preg_match('/^\d{6}$/', $code)) {
                $valid = verifyTotpCode(
                    $twofaSecret,
                    $code,
                    1,
                    6,
                    30,
                    'sha1'
                );
            }

            if (!$valid) {
                $valid = consumeBackupCode($pdo, $pendingUserId, $code);
            }

            if ($valid) {
                session_regenerate_id(true);

                $_SESSION["user_id"] = $user["id"];
                $_SESSION["user_name"] = $user["name"];
                $_SESSION["user_username"] = $user["username"];
                $_SESSION["logged_in"] = true;

                unset(
                    $_SESSION["pending_2fa_user_id"],
                    $_SESSION["pending_2fa_name"],
                    $_SESSION["pending_2fa_username"],
                    $_SESSION["pending_2fa_verified_at"]
                );

                // This is the event your homepage chart expects
                logAttackEvent(
                    "successful_login",
                    "low",
                    "verify_2fa.php",
                    [
                        "userId" => $user["id"],
                        "username" => $user["username"]
                    ]
                );

                // Optional extra audit event for specifically tracking 2FA completions
                logAttackEvent(
                    "successful_2fa_login",
                    "low",
                    "verify_2fa.php",
                    [
                        "userId" => $user["id"],
                        "username" => $user["username"]
                    ]
                );

                $displayName = trim((string) ($user["name"] ?? ""));
                if ($displayName === "") {
                    $displayName = (string) $user["username"];
                }

                if (function_exists("trackUserDevice")) {
                    $isNewDevice = trackUserDevice((int) $user["id"], $displayName);

                    if ($isNewDevice) {
                        logAttackEvent(
                            "new_device_login",
                            "high",
                            "verify_2fa.php",
                            [
                                "userId" => $user["id"],
                                "username" => $user["username"]
                            ]
                        );
                    }
                }

                header("Location: homepage.php");
                exit;
            } else {
                $message = "Invalid authenticator code or backup code.";

                logAttackEvent(
                    "failed_2fa_login",
                    "high",
                    "verify_2fa.php",
                    [
                        "userId" => $pendingUserId,
                        "username" => $pendingUsername,
                        "reason" => "Invalid TOTP or backup code"
                    ]
                );
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
    <title>Verify 2FA | Optimsecurity</title>
    <link rel="stylesheet" href="vault.css?v=30">
    <link rel="icon" href="/favicon.ico" type="image/x-icon">

    <link rel="icon" type="image/png" sizes="32x32" href="/favicon-32x32.png">
    <link rel="icon" type="image/png" sizes="16x16" href="/favicon-16x16.png">

    <link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png">
    <link rel="manifest" href="/site.webmanifest">
</head>
<body class="vault-body">
    <div class="vault-shell">
        <aside class="vault-sidebar">
            <div class="vault-sidebar-brand">
                <img src="optimsecuritylogo.png" alt="Optimsecurity Logo">
            </div>
            <nav class="vault-nav">
                <a class="vault-nav-item" href="login.php">Back to Login</a>
                <div class="vault-sidebar-spacer"></div>
                <a class="vault-nav-item logout" href="logout.php">Cancel Login</a>
            </nav>
        </aside>

        <main class="vault-main">
            <section class="vault-topbar">
                <div>
                    <div class="vault-badge">Security</div>
                    <h1>Verify 2FA</h1>
                    <p>Enter your current 6-digit authenticator code or one of your backup codes.</p>
                </div>
                <div class="vault-topbar-right">
                    <div class="vault-user-chip">@<?= htmlspecialchars($pendingUsername) ?></div>
                </div>
            </section>

            <div class="vault-content-card">
                <?php if ($message): ?>
                    <div class="vault-inline-message error"><?= htmlspecialchars($message) ?></div>
                <?php endif; ?>

                <div class="vault-stats-row">
                    <div class="vault-stat-card">
                        <span class="vault-stat-label">Account</span>
                        <span class="vault-stat-value"><?= htmlspecialchars($pendingUsername) ?></span>
                    </div>

                    <div class="vault-stat-card">
                        <span class="vault-stat-label">2FA Type</span>
                        <span class="vault-stat-value">Authenticator / Backup Code</span>
                    </div>

                    <div class="vault-stat-card">
                        <span class="vault-stat-label">Code Format</span>
                        <span class="vault-stat-value">6 digits / backup code</span>
                    </div>
                </div>

                <div class="vault-panel-card" style="margin-top: 20px;">
                    <div class="vault-panel-title">Two-Factor Verification</div>
                    <p style="color:#9bb3c3; margin-bottom:16px;">
                        Use Microsoft Authenticator, Google Authenticator, or a saved backup code.
                    </p>

                    <form method="post" autocomplete="off">
                        <div class="vault-form-group">
                            <label for="code">Authenticator Code or Backup Code</label>
                            <input
                                type="text"
                                id="code"
                                name="code"
                                maxlength="12"
                                autocomplete="one-time-code"
                                required
                            >
                        </div>

                        <div class="vault-actions-row" style="justify-content:flex-start; margin-top:20px;">
                            <button type="submit" class="vault-primary-btn">Verify</button>
                            <a href="logout.php" class="vault-secondary-btn">Cancel Login</a>
                        </div>
                    </form>
                </div>
            </div>
        </main>
    </div>
</body>
</html>
