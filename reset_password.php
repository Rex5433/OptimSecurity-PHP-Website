<?php
session_start();

header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Pragma: no-cache");
header("Expires: 0");

include "db.php";
require_once __DIR__ . "/recovery_helpers.php";

if (!isset($_SESSION["password_reset_user_id"], $_SESSION["password_reset_username"])) {
    header("Location: login.php");
    exit;
}

if (!$pdo) {
    die("Database connection failed.");
}

$userId = (int) $_SESSION["password_reset_user_id"];
$username = (string) $_SESSION["password_reset_username"];

$message = "";
$success = "";
$newRecoveryKeyToShow = "";

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $newPassword = $_POST["new_password"] ?? "";
    $confirmPassword = $_POST["confirm_password"] ?? "";

    if ($newPassword === "" || $confirmPassword === "") {
        $message = "Please fill in all fields.";
    } elseif (strlen($newPassword) < 8) {
        $message = "Password must be at least 8 characters.";
    } elseif (
        !preg_match('/[A-Z]/', $newPassword) ||
        !preg_match('/[a-z]/', $newPassword) ||
        !preg_match('/[0-9]/', $newPassword) ||
        !preg_match('/[\W_]/', $newPassword)
    ) {
        $message = "Password must contain an uppercase letter, lowercase letter, number, and special character.";
    } elseif ($newPassword !== $confirmPassword) {
        $message = "Passwords do not match.";
    } else {
        try {
            $pdo->beginTransaction();

            $newHash = password_hash($newPassword, PASSWORD_DEFAULT);

            $updateStmt = $pdo->prepare('
                UPDATE "Accounts"
                SET password = :password
                WHERE id = :id
            ');
            $updateStmt->execute([
                'password' => $newHash,
                'id' => $userId
            ]);

            markRecoveryKeyUsed($pdo, $userId);

            $newRecoveryKey = generateRecoveryKey();
            $saved = upsertRecoveryKey($pdo, $userId, $newRecoveryKey);

            if (!$saved) {
                throw new Exception("Could not rotate recovery key.");
            }

            $pdo->commit();

            $newRecoveryKeyToShow = $newRecoveryKey;
            $success = "Password reset successful. Save your new recovery key now.";

            unset($_SESSION["password_reset_user_id"], $_SESSION["password_reset_username"]);
        } catch (Throwable $e) {
            if ($pdo->inTransaction()) {
                $pdo->rollBack();
            }

            $message = "Could not reset password right now.";
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reset Password | Optimsecurity</title>
    <link rel="stylesheet" href="styles.css">
    <link rel="icon" href="/favicon.ico" type="image/x-icon">
    <link rel="icon" type="image/png" sizes="32x32" href="/favicon-32x32.png">
    <link rel="icon" type="image/png" sizes="16x16" href="/favicon-16x16.png">
    <link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png">
    <link rel="manifest" href="/site.webmanifest">
    <style>
        .recovery-key-box {
            margin-top: 16px;
            padding: 16px;
            border-radius: 14px;
            border: 1px solid rgba(39, 233, 181, 0.28);
            background: rgba(39, 233, 181, 0.08);
            color: #d9fff4;
            text-align: center;
            font-weight: 800;
            letter-spacing: 1px;
            word-break: break-word;
        }

        .recovery-note {
            margin-top: 12px;
            color: #b9d2dd;
            text-align: center;
            line-height: 1.5;
        }
    </style>
</head>
<body>
    <div class="login-wrapper">
        <div class="login-box">
            <h1>Reset Password</h1>

            <p class="bottom-link" style="margin-bottom: 14px;">
                @<?= htmlspecialchars($username) ?>
            </p>

            <?php if ($message): ?>
                <div class="login-error"><?= htmlspecialchars($message) ?></div>
            <?php endif; ?>

            <?php if ($success): ?>
                <div class="login-success"><?= htmlspecialchars($success) ?></div>
            <?php endif; ?>

            <?php if ($newRecoveryKeyToShow !== ""): ?>
                <div class="recovery-key-box">
                    <?= htmlspecialchars($newRecoveryKeyToShow) ?>
                </div>

                <div class="recovery-note">
                    This new recovery key is shown only once. Save it somewhere secure before leaving this page.
                </div>

                <div class="divider"></div>

                <p class="bottom-link">
                    <a href="login.php">Back to Login</a>
                </p>
            <?php else: ?>
                <form method="post">
                    <div class="form-group">
                        <label for="new_password">New Password</label>
                        <input
                            type="password"
                            id="new_password"
                            name="new_password"
                            placeholder="Enter new password"
                            required
                        >
                    </div>

                    <div class="form-group">
                        <label for="confirm_password">Confirm New Password</label>
                        <input
                            type="password"
                            id="confirm_password"
                            name="confirm_password"
                            placeholder="Confirm new password"
                            required
                        >
                    </div>

                    <button type="submit" class="login-submit">Update Password</button>
                </form>

                <div class="divider"></div>

                <p class="bottom-link">
                    <a href="login.php">Back to Login</a>
                </p>
            <?php endif; ?>
        </div>
    </div>
</body>
</html>
