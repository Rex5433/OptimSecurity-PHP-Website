<?php
session_start();

header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Pragma: no-cache");
header("Expires: 0");

if (!isset($_SESSION["user_id"])) {
    header("Location: login.php");
    exit;
}

include "db.php";
require_once __DIR__ . "/twofa_helpers.php";

if (empty($_SESSION["csrf_token"])) {
    $_SESSION["csrf_token"] = bin2hex(random_bytes(32));
}

$userId = (int) $_SESSION["user_id"];
$usernameChip = $_SESSION["user_username"] ?? "user";
$message = "";
$success = "";

if (!$pdo) {
    die("Database connection failed.");
}

$stmt = $pdo->prepare('
    SELECT id, username, email, password, twofa_enabled, twofa_secret, twofa_created_at
    FROM "Accounts"
    WHERE id = :id
    LIMIT 1
');
$stmt->execute(['id' => $userId]);
$user = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$user) {
    die("User not found.");
}

$twofaRaw = $user["twofa_enabled"] ?? false;
$twofaEnabled = (
    $twofaRaw === true ||
    $twofaRaw === 1 ||
    $twofaRaw === "1" ||
    $twofaRaw === "t" ||
    $twofaRaw === "true"
);

if ($_SERVER["REQUEST_METHOD"] === "POST" && $twofaEnabled) {
    if (
        empty($_POST["csrf_token"]) ||
        !hash_equals($_SESSION["csrf_token"], $_POST["csrf_token"])
    ) {
        $message = "Invalid CSRF token.";
    } else {
        $password = $_POST["password"] ?? "";
        $code = strtoupper(trim($_POST["code"] ?? ""));
        $valid = false;

        if ($password === "" || $code === "") {
            $message = "Fill in both fields.";
        } elseif (!password_verify($password, (string) $user["password"])) {
            $message = "Incorrect current password.";
        } else {
            if (preg_match('/^\d{6}$/', $code)) {
                $valid = verifyTotpCode(
                    (string) $user["twofa_secret"],
                    $code,
                    1,
                    6,
                    30,
                    'sha1'
                );
            }

            if (!$valid) {
                $valid = consumeBackupCode($pdo, $userId, $code);
            }

            if (!$valid) {
                $message = "Invalid authenticator or backup code.";
            } else {
                $update = $pdo->prepare('
                    UPDATE "Accounts"
                    SET twofa_enabled = false,
                        twofa_secret = NULL,
                        twofa_backup_codes = NULL,
                        twofa_created_at = NULL
                    WHERE id = :id
                ');
                $update->execute(['id' => $userId]);

                $success = "Two-factor authentication has been disabled.";

                $stmt = $pdo->prepare('
                    SELECT id, username, email, password, twofa_enabled, twofa_secret, twofa_created_at
                    FROM "Accounts"
                    WHERE id = :id
                    LIMIT 1
                ');
                $stmt->execute(['id' => $userId]);
                $user = $stmt->fetch(PDO::FETCH_ASSOC);

                $twofaRaw = $user["twofa_enabled"] ?? false;
                $twofaEnabled = (
                    $twofaRaw === true ||
                    $twofaRaw === 1 ||
                    $twofaRaw === "1" ||
                    $twofaRaw === "t" ||
                    $twofaRaw === "true"
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
    <title>Disable 2FA</title>
    <meta name="csrf-token" content="<?= htmlspecialchars($_SESSION["csrf_token"]) ?>">
    <link rel="stylesheet" href="vault.css?v=30">
</head>
<body class="vault-body">
    <div class="vault-shell">
        <aside class="vault-sidebar">
            <div class="vault-sidebar-title">Dashboard</div>
            <nav class="vault-nav">
                <a class="vault-nav-item" href="homepage.php">Home</a>
                <a class="vault-nav-item" href="password_checker.php">Password Check</a>
                <a class="vault-nav-item" href="password_generator.php">Password Gen</a>
                <a class="vault-nav-item" href="vault.php">Vault</a>
                <a class="vault-nav-item" href="phishing_toolkit.php">Phishing Toolkit</a>
                <a class="vault-nav-item" href="about.php">About Me</a>
                <div class="vault-sidebar-spacer"></div>
                <a class="vault-nav-item active" href="security_settings.php">Security Settings</a>
                <a class="vault-nav-item logout" href="logout.php">Logout</a>
            </nav>
        </aside>

        <main class="vault-main">
            <section class="vault-topbar">
                <div>
                    <div class="vault-badge">Security</div>
                    <h1>Disable 2FA</h1>
                    <p>Remove authenticator-based two-factor authentication from your account.</p>
                </div>
                <div class="vault-topbar-right">
                    <div class="vault-user-chip">@<?= htmlspecialchars($usernameChip) ?></div>
                </div>
            </section>

            <div class="vault-content-card">
                <?php if ($message): ?>
                    <div class="vault-inline-message error"><?= htmlspecialchars($message) ?></div>
                <?php endif; ?>

                <?php if ($success): ?>
                    <div class="vault-inline-message success"><?= htmlspecialchars($success) ?></div>
                <?php endif; ?>

                <div class="vault-stats-row">
                    <div class="vault-stat-card">
                        <span class="vault-stat-label">Account</span>
                        <span class="vault-stat-value"><?= htmlspecialchars((string) $user["username"]) ?></span>
                    </div>

                    <div class="vault-stat-card">
                        <span class="vault-stat-label">2FA Status</span>
                        <span class="vault-stat-value"><?= $twofaEnabled ? "Enabled" : "Disabled" ?></span>
                    </div>

                    <div class="vault-stat-card">
                        <span class="vault-stat-label">Code Format</span>
                        <span class="vault-stat-value">6 digits / 30 seconds</span>
                    </div>
                </div>

                <div class="vault-panel-card" style="margin-top: 20px;">
                    <div class="vault-panel-title">Two-Factor Authentication</div>

                    <?php if (!$twofaEnabled): ?>
                        <p style="color:#9bb3c3; margin-bottom:16px;">
                            2FA is not currently enabled on this account.
                        </p>

                        <div class="vault-actions-row" style="justify-content:flex-start;">
                            <a href="setup_2fa.php" class="vault-primary-btn">Enable 2FA</a>
                            <a href="security_settings.php" class="vault-secondary-btn">Back to Security Settings</a>
                        </div>
                    <?php else: ?>
                        <p style="color:#9bb3c3; margin-bottom:16px;">
                            Enter your current password and either your authenticator code or one of your backup codes to disable 2FA.
                        </p>

                        <form method="post">
                            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION["csrf_token"]) ?>">

                            <div class="vault-form-group">
                                <label for="password">Current Password</label>
                                <input type="password" id="password" name="password" required>
                            </div>

                            <div class="vault-form-group">
                                <label for="code">Authenticator Code or Backup Code</label>
                                <input
                                    type="text"
                                    id="code"
                                    name="code"
                                    maxlength="12"
                                    inputmode="numeric"
                                    autocomplete="one-time-code"
                                    required
                                >
                            </div>

                            <div class="vault-actions-row" style="justify-content:flex-start; margin-top:20px;">
                                <button type="submit" class="vault-action-btn danger">Disable 2FA</button>
                                <a href="security_settings.php" class="vault-secondary-btn">Cancel</a>
                            </div>
                        </form>

                        <div class="vault-panel-card" style="margin-top:20px;">
                            <div class="vault-panel-title">Current 2FA Settings</div>
                            <p style="color:#9bb3c3; line-height:1.7; margin-bottom:0;">
                                Authenticator compatibility: <strong>Microsoft Authenticator / Google Authenticator</strong><br>
                                Algorithm: <strong>SHA1</strong><br>
                                Digits: <strong>6</strong><br>
                                Period: <strong>30 seconds</strong><br>
                                Enabled on:
                                <strong>
                                    <?= !empty($user["twofa_created_at"]) ? htmlspecialchars((string) $user["twofa_created_at"]) : "Not Set" ?>
                                </strong>
                            </p>
                        </div>
                    <?php endif; ?>
                </div>
            </div>
        </main>
    </div>
</body>
</html>