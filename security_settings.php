<?php
session_start();

header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Pragma: no-cache");
header("Expires: 0");

if (!isset($_SESSION["user_id"])) {
    if (
        !empty($_SERVER["HTTP_X_REQUESTED_WITH"]) &&
        strtolower($_SERVER["HTTP_X_REQUESTED_WITH"]) === "xmlhttprequest"
    ) {
        header("Content-Type: application/json");
        http_response_code(401);
        echo json_encode([
            "ok" => false,
            "error" => "Not logged in."
        ]);
        exit;
    }

    header("Location: login.php");
    exit;
}

include "db.php";
require_once __DIR__ . "/twofa_helpers.php";

if (empty($_SESSION["csrf_token"])) {
    $_SESSION["csrf_token"] = bin2hex(random_bytes(32));
}

function is_ajax_request(): bool
{
    return !empty($_SERVER["HTTP_X_REQUESTED_WITH"]) &&
        strtolower($_SERVER["HTTP_X_REQUESTED_WITH"]) === "xmlhttprequest";
}

function json_response(array $payload, int $status = 200): void
{
    http_response_code($status);
    header("Content-Type: application/json");
    echo json_encode($payload);
    exit;
}

$username = $_SESSION["user_username"] ?? "user";
$message = "";
$success = "";
$backupCodes = $_SESSION["twofa_plain_backup_codes"] ?? [];
unset($_SESSION["twofa_plain_backup_codes"]);

if (!$pdo) {
    if (is_ajax_request()) {
        json_response([
            "ok" => false,
            "error" => "Database connection failed."
        ], 500);
    }

    die("Database connection failed.");
}

$userId = (int) $_SESSION["user_id"];

$stmt = $pdo->prepare('
    SELECT id, username, password, twofa_enabled, twofa_secret, twofa_backup_codes, twofa_created_at
    FROM "Accounts"
    WHERE id = :id
    LIMIT 1
');
$stmt->execute(['id' => $userId]);
$user = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$user) {
    if (is_ajax_request()) {
        json_response([
            "ok" => false,
            "error" => "User not found."
        ], 404);
    }

    die("User not found.");
}

$vaultProfileStmt = $pdo->prepare('
    SELECT id, wrapped_vault_key, wrapped_vault_key_iv
    FROM public.vault_profile
    WHERE user_id = :user_id
    LIMIT 1
');
$vaultProfileStmt->execute(['user_id' => $userId]);
$vaultProfile = $vaultProfileStmt->fetch(PDO::FETCH_ASSOC);
$vaultProfileExists = (bool) $vaultProfile;

$twofaRaw = $user["twofa_enabled"] ?? false;
$twofaEnabled = (
    $twofaRaw === true ||
    $twofaRaw === 1 ||
    $twofaRaw === "1" ||
    $twofaRaw === "t" ||
    $twofaRaw === "true"
);

if (!$twofaEnabled && empty($_SESSION["pending_twofa_secret"])) {
    $_SESSION["pending_twofa_secret"] = randomBase32Secret();
}

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $isAjax = is_ajax_request();

    if (
        empty($_POST["csrf_token"]) ||
        !hash_equals($_SESSION["csrf_token"], $_POST["csrf_token"])
    ) {
        if ($isAjax) {
            json_response([
                "ok" => false,
                "error" => "Invalid CSRF token."
            ], 403);
        }

        $message = "Invalid CSRF token.";
    } else {
        $action = $_POST["action"] ?? "";

        if ($action === "enable_2fa") {
            if ($twofaEnabled) {
                $message = "2FA is already enabled.";
            } else {
                $code = trim($_POST["twofa_code"] ?? "");
                $pendingSecret = (string) ($_SESSION["pending_twofa_secret"] ?? "");

                if (isset($_POST["regenerate_twofa"])) {
                    $_SESSION["pending_twofa_secret"] = randomBase32Secret();
                    header("Location: security_settings.php");
                    exit;
                }

                if ($pendingSecret === "") {
                    $_SESSION["pending_twofa_secret"] = randomBase32Secret();
                    $message = "A new 2FA secret was created. Please scan the QR code and try again.";
                } elseif ($code === "") {
                    $message = "Enter the 6-digit code from your authenticator app.";
                } elseif (!preg_match('/^\d{6}$/', $code)) {
                    $message = "Enter a valid 6-digit code.";
                } elseif (!verifyTotpCode($pendingSecret, $code, 1, 6, 30, 'sha1')) {
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
                        'secret' => $pendingSecret,
                        'backup_codes' => $backupHashJson,
                        'id' => $userId,
                    ]);

                    unset($_SESSION["pending_twofa_secret"]);
                    $_SESSION["twofa_plain_backup_codes"] = $backupCodes;

                    $success = "Two-factor authentication has been enabled.";
                }
            }
        }

        if ($action === "change_password") {
            $currentPassword = $_POST["current_password"] ?? "";
            $newPassword = $_POST["new_password"] ?? "";
            $confirmPassword = $_POST["confirm_password"] ?? "";
            $wrappedVaultKey = trim((string) ($_POST["wrapped_vault_key"] ?? ""));
            $wrappedVaultKeyIv = trim((string) ($_POST["wrapped_vault_key_iv"] ?? ""));

            if ($currentPassword === "" || $newPassword === "" || $confirmPassword === "") {
                $errorText = "Fill in all password fields.";

                if ($isAjax) {
                    json_response(["ok" => false, "error" => $errorText], 400);
                }

                $message = $errorText;
            } elseif (!password_verify($currentPassword, (string) $user["password"])) {
                $errorText = "Current password is incorrect.";

                if ($isAjax) {
                    json_response(["ok" => false, "error" => $errorText], 400);
                }

                $message = $errorText;
            } elseif (strlen($newPassword) < 8) {
                $errorText = "New password must be at least 8 characters.";

                if ($isAjax) {
                    json_response(["ok" => false, "error" => $errorText], 400);
                }

                $message = $errorText;
            } elseif ($newPassword !== $confirmPassword) {
                $errorText = "New passwords do not match.";

                if ($isAjax) {
                    json_response(["ok" => false, "error" => $errorText], 400);
                }

                $message = $errorText;
            } elseif ($vaultProfileExists && ($wrappedVaultKey === "" || $wrappedVaultKeyIv === "")) {
                $errorText = "Vault re-wrap data is missing. Please try again.";

                if ($isAjax) {
                    json_response(["ok" => false, "error" => $errorText], 400);
                }

                $message = $errorText;
            } else {
                try {
                    $pdo->beginTransaction();

                    $newHash = password_hash($newPassword, PASSWORD_DEFAULT);

                    $updateAccount = $pdo->prepare('
                        UPDATE "Accounts"
                        SET password = :password
                        WHERE id = :id
                    ');
                    $updateAccount->execute([
                        'password' => $newHash,
                        'id' => $userId
                    ]);

                    if ($vaultProfileExists) {
                        $updateVaultProfile = $pdo->prepare('
                            UPDATE public.vault_profile
                            SET wrapped_vault_key = :wrapped_vault_key,
                                wrapped_vault_key_iv = :wrapped_vault_key_iv,
                                updated_at = NOW()
                            WHERE user_id = :user_id
                        ');
                        $updateVaultProfile->execute([
                            'wrapped_vault_key' => $wrappedVaultKey,
                            'wrapped_vault_key_iv' => $wrappedVaultKeyIv,
                            'user_id' => $userId
                        ]);
                    }

                    $pdo->commit();

                    if ($isAjax) {
                        json_response([
                            "ok" => true,
                            "message" => "Password updated successfully."
                        ]);
                    }

                    $success = "Password updated successfully.";
                } catch (Throwable $e) {
                    if ($pdo->inTransaction()) {
                        $pdo->rollBack();
                    }

                    if ($isAjax) {
                        json_response([
                            "ok" => false,
                            "error" => "Could not update password right now."
                        ], 500);
                    }

                    $message = "Could not update password right now.";
                }
            }
        }

        if ($action === "delete_account") {
            $deletePassword = $_POST["delete_password"] ?? "";
            $deleteConfirm = trim($_POST["delete_confirm"] ?? "");

            if ($deletePassword === "" || $deleteConfirm === "") {
                $message = "Fill in all delete account fields.";
            } elseif (!password_verify($deletePassword, (string) $user["password"])) {
                $message = "Password is incorrect.";
            } elseif ($deleteConfirm !== "DELETE") {
                $message = "Type DELETE to confirm account removal.";
            } else {
                try {
                    $pdo->beginTransaction();

                    $deleteVault = $pdo->prepare('DELETE FROM public.vault_item WHERE user_id = :user_id');
                    $deleteVault->execute(['user_id' => $userId]);

                    $deleteProfile = $pdo->prepare('DELETE FROM public.vault_profile WHERE user_id = :user_id');
                    $deleteProfile->execute(['user_id' => $userId]);

                    $deleteAccount = $pdo->prepare('DELETE FROM "Accounts" WHERE id = :id');
                    $deleteAccount->execute(['id' => $userId]);

                    $pdo->commit();

                    session_unset();
                    session_destroy();

                    header("Location: login.php");
                    exit;
                } catch (Throwable $e) {
                    if ($pdo->inTransaction()) {
                        $pdo->rollBack();
                    }

                    $message = "Could not delete account right now.";
                }
            }
        }
    }
}

$stmt = $pdo->prepare('
    SELECT id, username, twofa_enabled, twofa_secret, twofa_backup_codes, twofa_created_at
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

$dbTwofaSecret = trim((string) ($user["twofa_secret"] ?? ""));

if ($twofaEnabled) {
    if (!empty($_SESSION["pending_twofa_secret"])) {
        unset($_SESSION["pending_twofa_secret"]);
    }
    $activeTwofaSecret = $dbTwofaSecret;
} else {
    if (empty($_SESSION["pending_twofa_secret"])) {
        $_SESSION["pending_twofa_secret"] = randomBase32Secret();
    }
    $activeTwofaSecret = (string) $_SESSION["pending_twofa_secret"];
}

$issuerRaw = 'Security Dashboard';
$accountRaw = (string) ($user["username"] ?? 'user');

$qrUrl = '';
if ($activeTwofaSecret !== '') {
    $otpauth = 'otpauth://totp/' . rawurlencode($issuerRaw . ':' . $accountRaw)
        . '?secret=' . rawurlencode($activeTwofaSecret)
        . '&issuer=' . rawurlencode($issuerRaw)
        . '&algorithm=SHA1'
        . '&digits=6'
        . '&period=30';

    $qrUrl = 'https://api.qrserver.com/v1/create-qr-code/?size=280x280&data=' . urlencode($otpauth);
}
?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Settings</title>
    <meta name="csrf-token" content="<?= htmlspecialchars($_SESSION["csrf_token"]) ?>">
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
                    <h1>Security Settings</h1>
                    <p>Manage your account security, 2FA, password, and account access.</p>
                </div>
                <div class="vault-topbar-right">
                    <div class="vault-user-chip">@<?= htmlspecialchars($username) ?></div>
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
                        <span class="vault-stat-label">2FA Enabled On</span>
                        <span class="vault-stat-value">
                            <?= !empty($user["twofa_created_at"])
                                ? date("M j, Y", strtotime($user["twofa_created_at"]))
                                : "Not Set" ?>
                        </span>
                    </div>
                </div>

                <?php if (!empty($backupCodes)): ?>
                    <div class="vault-panel-card" style="margin-top:20px;">
                        <div class="vault-panel-title">Backup Codes</div>
                        <p style="color:#9bb3c3; margin-bottom:16px;">
                            Save these backup codes somewhere safe. They are shown only once.
                        </p>

                        <div class="vault-grid">
                            <?php foreach ($backupCodes as $code): ?>
                                <div class="vault-stat-card" style="text-align:center; font-weight:800; letter-spacing:1px;">
                                    <?= htmlspecialchars($code) ?>
                                </div>
                            <?php endforeach; ?>
                        </div>
                    </div>
                <?php endif; ?>

                <div class="vault-grid" style="margin-top: 20px;">
                    <div class="vault-panel-card">
                        <div class="vault-panel-title">Two-Factor Authentication</div>
                        <p style="color:#9bb3c3; margin-bottom:16px;">
                            Enable or disable TOTP-based 2FA for your login.
                        </p>

                        <?php if ($twofaEnabled): ?>
                            <div class="vault-actions-row" style="justify-content:flex-start;">
                                <a href="disable_2fa.php" class="vault-primary-btn">Disable 2FA</a>
                            </div>

                            <?php if ($qrUrl !== ''): ?>
                                <div style="margin-top:20px;">
                                    <p style="color:#9bb3c3; margin-bottom:14px;">
                                        Scan this QR code in Microsoft Authenticator or Google Authenticator to add this account
                                        again on another device.
                                    </p>

                                    <div
                                        style="display:flex; justify-content:center; align-items:center; background:#041c2b; border:1px solid #25475b; border-radius:16px; padding:18px;">
                                        <img src="<?= htmlspecialchars($qrUrl) ?>" alt="2FA QR Code"
                                            style="width:240px; max-width:100%; height:auto; background:#fff; border-radius:12px; padding:12px; display:block;">
                                    </div>
                                </div>
                            <?php endif; ?>
                        <?php else: ?>
                            <p style="color:#9bb3c3; margin-bottom:14px;">
                                Scan this QR code in Microsoft Authenticator or Google Authenticator, then enter the 6-digit
                                code below to enable 2FA right here.
                            </p>

                            <?php if ($qrUrl !== ''): ?>
                                <div
                                    style="display:flex; justify-content:center; align-items:center; background:#041c2b; border:1px solid #25475b; border-radius:16px; padding:18px; margin-bottom:18px;">
                                    <img src="<?= htmlspecialchars($qrUrl) ?>" alt="2FA QR Code"
                                        style="width:240px; max-width:100%; height:auto; background:#fff; border-radius:12px; padding:12px; display:block;">
                                </div>
                            <?php endif; ?>

                            <form method="post">
                                <input type="hidden" name="csrf_token"
                                    value="<?= htmlspecialchars($_SESSION["csrf_token"]) ?>">
                                <input type="hidden" name="action" value="enable_2fa">

                                <div class="vault-form-group">
                                    <label for="twofa_code">Enter the 6-digit code from your app</label>
                                    <input type="text" id="twofa_code" name="twofa_code" maxlength="6" inputmode="numeric"
                                        pattern="[0-9]{6}" autocomplete="one-time-code" required>
                                </div>

                                <div class="vault-actions-row" style="justify-content:flex-start; margin-top:20px;">
                                    <button type="submit" class="vault-primary-btn">Enable 2FA</button>
                                    <button type="submit" name="regenerate_twofa" value="1"
                                        class="vault-secondary-btn">Generate New Secret</button>
                                </div>
                            </form>
                        <?php endif; ?>
                    </div>

                    <div class="vault-panel-card">
                        <div class="vault-panel-title">Change Password</div>

                        <form method="post" id="changePasswordForm">
                            <input type="hidden" name="csrf_token"
                                value="<?= htmlspecialchars($_SESSION["csrf_token"]) ?>">
                            <input type="hidden" name="action" value="change_password">
                            <input type="hidden" name="wrapped_vault_key" id="wrapped_vault_key" value="">
                            <input type="hidden" name="wrapped_vault_key_iv" id="wrapped_vault_key_iv" value="">

                            <div class="vault-form-group">
                                <label for="current_password">Current Password</label>
                                <input type="password" id="current_password" name="current_password" required>
                            </div>

                            <div class="vault-form-group">
                                <label for="new_password">New Password</label>
                                <input type="password" id="new_password" name="new_password" required>
                            </div>

                            <div class="vault-form-group">
                                <label for="confirm_password">Confirm New Password</label>
                                <input type="password" id="confirm_password" name="confirm_password" required>
                            </div>

                            <div class="vault-actions-row" style="justify-content:flex-start;">
                                <button type="submit" class="vault-primary-btn" id="updatePasswordBtn">Update
                                    Password</button>
                            </div>
                        </form>
                    </div>
                </div>

                <div class="vault-panel-card" style="margin-top: 20px;">
                    <div class="vault-panel-title" style="color:#ff9b9b;">Delete Account</div>
                    <p style="color:#9bb3c3; margin-bottom:16px;">
                        This permanently deletes your account, vault items, and vault profile.
                    </p>

                    <form method="post">
                        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION["csrf_token"]) ?>">
                        <input type="hidden" name="action" value="delete_account">

                        <div class="vault-grid">
                            <div class="vault-form-group">
                                <label for="delete_password">Current Password</label>
                                <input type="password" id="delete_password" name="delete_password" required>
                            </div>

                            <div class="vault-form-group">
                                <label for="delete_confirm">Type DELETE to confirm</label>
                                <input type="text" id="delete_confirm" name="delete_confirm" required>
                            </div>
                        </div>

                        <div class="vault-actions-row" style="justify-content:flex-start;">
                            <button type="submit" class="vault-action-btn danger">Delete Account</button>
                        </div>
                    </form>
                </div>
            </div>
        </main>
    </div>

    <script src="vault_crypto.js"></script>
    <script>
        (() => {
            const form = document.getElementById("changePasswordForm");
            const currentPasswordInput = document.getElementById("current_password");
            const newPasswordInput = document.getElementById("new_password");
            const wrappedVaultKeyInput = document.getElementById("wrapped_vault_key");
            const wrappedVaultKeyIvInput = document.getElementById("wrapped_vault_key_iv");

            if (!form) return;

            form.addEventListener("submit", async (event) => {
                event.preventDefault();

                const currentPassword = currentPasswordInput.value || "";
                const newPassword = newPasswordInput.value || "";

                try {
                    const profileRes = await fetch("vault_profile.php", {
                        headers: {
                            "X-Requested-With": "XMLHttpRequest"
                        }
                    });

                    const raw = await profileRes.text();
                    const data = raw ? JSON.parse(raw) : {};

                    if (data.exists && data.profile) {
                        const rewrapped = await window.VaultCrypto.rewrapVaultKey(
                            currentPassword,
                            newPassword,
                            data.profile
                        );

                        wrappedVaultKeyInput.value = rewrapped.wrapped_vault_key;
                        wrappedVaultKeyIvInput.value = rewrapped.wrapped_vault_key_iv;
                    }

                    sessionStorage.setItem("vault_login_password", newPassword);
                    form.submit();
                } catch (error) {
                    alert("Could not re-wrap vault key. Make sure your current password is correct and your vault profile is valid.");
                }
            });
        })();
    </script>
</body>

</html>