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
$backupCodes = $_SESSION["twofa_plain_backup_codes"] ?? [];
unset($_SESSION["twofa_plain_backup_codes"]);

if (!$pdo) {
    die("Database connection failed.");
}

$stmt = $pdo->prepare('
    SELECT id, username, email, twofa_enabled, twofa_secret, twofa_created_at
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
$alreadyEnabled = (
    $twofaRaw === true ||
    $twofaRaw === 1 ||
    $twofaRaw === "1" ||
    $twofaRaw === "t" ||
    $twofaRaw === "true"
);

if (!$alreadyEnabled && empty($_SESSION["pending_twofa_secret"])) {
    $_SESSION["pending_twofa_secret"] = randomBase32Secret();
}

if ($_SERVER["REQUEST_METHOD"] === "POST" && !$alreadyEnabled) {
    if (
        empty($_POST["csrf_token"]) ||
        !hash_equals($_SESSION["csrf_token"], $_POST["csrf_token"])
    ) {
        $message = "Invalid CSRF token.";
    } else {
        if (isset($_POST["regenerate"])) {
            $_SESSION["pending_twofa_secret"] = randomBase32Secret();
            header("Location: setup_2fa.php");
            exit;
        }

        $code = trim($_POST["code"] ?? "");
        $secret = (string) ($_SESSION["pending_twofa_secret"] ?? "");

        if ($code === "") {
            $message = "Enter the 6-digit code from your authenticator app.";
        } elseif (!preg_match('/^\d{6}$/', $code)) {
            $message = "Enter a valid 6-digit code.";
        } elseif ($secret === "") {
            $message = "No pending 2FA secret found. Please generate a new secret.";
        } elseif (!verifyTotpCode($secret, $code, 1, 6, 30, 'sha1')) {
            $message = "Invalid authentication code.";
        } else {
            $backupCodes = generateBackupCodes(8);
            $backupHashJson = hashBackupCodes($backupCodes);

            $update = $pdo->prepare('
                UPDATE "Accounts"
                SET twofa_enabled = true,
                    twofa_secret = :secret,
                    twofa_backup_codes = :backup_codes,
                    twofa_created_at = NOW()
                WHERE id = :id
            ');
            $update->execute([
                'secret' => $secret,
                'backup_codes' => $backupHashJson,
                'id' => $userId,
            ]);

            unset($_SESSION["pending_twofa_secret"]);
            $_SESSION["twofa_plain_backup_codes"] = $backupCodes;

            header("Location: setup_2fa.php");
            exit;
        }
    }
}

$stmt = $pdo->prepare('
    SELECT id, username, email, twofa_enabled, twofa_secret, twofa_created_at
    FROM "Accounts"
    WHERE id = :id
    LIMIT 1
');
$stmt->execute(['id' => $userId]);
$user = $stmt->fetch(PDO::FETCH_ASSOC);

$twofaRaw = $user["twofa_enabled"] ?? false;
$alreadyEnabled = (
    $twofaRaw === true ||
    $twofaRaw === 1 ||
    $twofaRaw === "1" ||
    $twofaRaw === "t" ||
    $twofaRaw === "true"
);

$accountRaw = (string) ($user["username"] ?? ("user-" . $userId));
$secretDisplay = $alreadyEnabled
    ? trim((string) ($user["twofa_secret"] ?? ""))
    : (string) ($_SESSION["pending_twofa_secret"] ?? "");

$issuerRaw = 'Security Dashboard';
$qrUrl = '';

if ($secretDisplay !== '') {
    $otpauth = 'otpauth://totp/' . rawurlencode($issuerRaw . ':' . $accountRaw)
        . '?secret=' . rawurlencode($secretDisplay)
        . '&issuer=' . rawurlencode($issuerRaw)
        . '&algorithm=SHA1'
        . '&digits=6'
        . '&period=30';

    $qrUrl = 'https://api.qrserver.com/v1/create-qr-code/?size=300x300&data=' . urlencode($otpauth);
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Setup 2FA</title>
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
                    <div class="vault-badge">Security Settings</div>
                    <h1>Set up 2FA</h1>
                    <p>Scan the QR code with Microsoft Authenticator or Google Authenticator, then enter the 6-digit code.</p>
                </div>
                <div class="vault-topbar-right">
                    <div class="vault-user-chip">@<?= htmlspecialchars($usernameChip) ?></div>
                </div>
            </section>

            <div class="vault-content-card">
                <?php if ($message): ?>
                    <div class="vault-inline-message error"><?= htmlspecialchars($message) ?></div>
                <?php endif; ?>

                <?php if ($alreadyEnabled && !empty($backupCodes)): ?>
                    <div class="vault-inline-message success">
                        2FA is enabled. Save these backup codes somewhere safe. They are shown only once.
                    </div>

                    <div class="vault-grid" style="margin-top:20px;">
                        <?php foreach ($backupCodes as $code): ?>
                            <div class="vault-stat-card" style="text-align:center; font-weight:800; letter-spacing:1px;">
                                <?= htmlspecialchars($code) ?>
                            </div>
                        <?php endforeach; ?>
                    </div>

                    <div class="vault-actions-row" style="justify-content:flex-start; margin-top:20px;">
                        <a href="security_settings.php" class="vault-primary-btn">Back to Security Settings</a>
                    </div>

                <?php elseif ($alreadyEnabled): ?>
                    <div class="vault-inline-message success">2FA is already enabled on your account.</div>

                    <div class="vault-actions-row" style="justify-content:flex-start; margin-top:20px;">
                        <a href="disable_2fa.php" class="vault-primary-btn">Disable 2FA</a>
                        <a href="security_settings.php" class="vault-secondary-btn">Back to Security Settings</a>
                    </div>

                <?php else: ?>
                    <div class="vault-panel-card" style="margin-top:20px;">
                        <div class="vault-panel-title">Authenticator Setup</div>
                        <p style="color:#9bb3c3; margin-bottom:16px;">
                            Scan this QR code in your authenticator app.
                        </p>

                        <?php if ($qrUrl !== ''): ?>
                            <div style="display:flex; justify-content:center; align-items:center; background:#041c2b; border:1px solid #25475b; border-radius:16px; padding:18px; margin-bottom:20px;">
                                <img
                                    src="<?= htmlspecialchars($qrUrl) ?>"
                                    alt="2FA QR Code"
                                    style="width:260px; max-width:100%; height:auto; background:#fff; border-radius:12px; padding:12px; display:block;"
                                >
                            </div>
                        <?php endif; ?>

                        <form method="post">
                            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION["csrf_token"]) ?>">

                            <div class="vault-form-group">
                                <label for="code">Enter the 6-digit code from your app</label>
                                <input
                                    type="text"
                                    id="code"
                                    name="code"
                                    maxlength="6"
                                    inputmode="numeric"
                                    pattern="[0-9]{6}"
                                    autocomplete="one-time-code"
                                    required
                                >
                            </div>

                            <div class="vault-actions-row" style="justify-content:flex-start; margin-top:20px;">
                                <button type="submit" class="vault-primary-btn">Enable 2FA</button>
                                <button type="submit" name="regenerate" value="1" class="vault-secondary-btn">Generate New Secret</button>
                            </div>

                            <div class="vault-actions-row" style="justify-content:flex-start; margin-top:16px;">
                                <a href="security_settings.php" class="vault-secondary-btn">Cancel</a>
                            </div>
                        </form>
                    </div>
                <?php endif; ?>
            </div>
        </main>
    </div>
</body>
</html>