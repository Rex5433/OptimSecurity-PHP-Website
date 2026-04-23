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
$vaultPreserved = false;

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $newPassword = $_POST["new_password"] ?? "";
    $confirmPassword = $_POST["confirm_password"] ?? "";

    if ($recoveryKeyInput === "" || $newPassword === "" || $confirmPassword === "") {
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
            $row = getRecoveryRowByUsername($pdo, $username);

            if (!$row || !verifyRecoveryKey($recoveryKeyInput, (string) $row["recovery_key_hash"])) {
                $message = "Invalid recovery key.";
            } else {
                $pdo->beginTransaction();

                $userStmt = $pdo->prepare('
                    SELECT id, username, name
                    FROM "Accounts"
                    WHERE id = :id
                    LIMIT 1
                ');
                $userStmt->execute(['id' => $userId]);
                $userRow = $userStmt->fetch(PDO::FETCH_ASSOC);

                if (!$userRow) {
                    throw new Exception("User not found during password reset.");
                }

                $displayName = trim((string) ($userRow["name"] ?? ""));
                if ($displayName === "") {
                    $displayName = (string) $userRow["username"];
                }

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

                $vaultProfileStmt = $pdo->prepare('
                    SELECT
                        user_id,
                        vault_salt,
                        vault_iterations,
                        vault_key_check,
                        wrapped_vault_key,
                        wrapped_vault_key_iv,
                        wrapped_vault_key_recovery,
                        wrapped_vault_key_recovery_iv
                    FROM public.vault_profile
                    WHERE user_id = :user_id
                    LIMIT 1
                ');
                $vaultProfileStmt->execute([
                    'user_id' => $userId
                ]);
                $vaultProfile = $vaultProfileStmt->fetch(PDO::FETCH_ASSOC);

                if ($vaultProfile) {
                    $vaultPreserved = true;
                }

                markRecoveryKeyUsed($pdo, $userId);

                $newRecoveryKey = generateRecoveryKey();
                $saved = upsertRecoveryKey($pdo, $userId, $newRecoveryKey);

                if (!$saved) {
                    throw new Exception("Could not rotate recovery key.");
                }

                if ($vaultProfile) {
                    $touchStmt = $pdo->prepare('
                        UPDATE public.vault_profile
                        SET updated_at = NOW()
                        WHERE user_id = :user_id
                    ');
                    $touchStmt->execute([
                        'user_id' => $userId
                    ]);
                }

                $pdo->commit();

                $_SESSION["password_reset_recovery_key"] = $recoveryKeyInput;
                $_SESSION["password_reset_new_password"] = $newPassword;
                $_SESSION["password_reset_new_recovery_key"] = $newRecoveryKey;
                $_SESSION["password_reset_username_done"] = (string) $userRow["username"];
                $_SESSION["password_reset_vault_preserved"] = $vaultPreserved ? "1" : "0";

                session_regenerate_id(true);

                $_SESSION["user_id"] = (int) $userRow["id"];
                $_SESSION["user_username"] = (string) $userRow["username"];
                $_SESSION["user_name"] = $displayName;
                $_SESSION["logged_in"] = true;

                unset(
                    $_SESSION["password_reset_user_id"],
                    $_SESSION["password_reset_username"]
                );

                header("Location: reset_password_finalize.php");
                exit;
            }
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

            <form method="post">
                <div class="form-group">
                    <label for="recovery_key">Recovery Key</label>
                    <input
                        type="text"
                        id="recovery_key"
                        name="recovery_key"
                        placeholder="Enter your recovery key"
                        required
                    >
                </div>

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
        </div>
    </div>
</body>
</html>
