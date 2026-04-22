<?php
session_start();

include "db.php";
require_once __DIR__ . "/recovery_helpers.php";
require_once __DIR__ . "/attack_helpers.php";

if (!isset($_SESSION["password_reset_user_id"], $_SESSION["password_reset_username"])) {
    header("Location: forgot_password.php");
    exit;
}

$message = "";

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $newPassword = $_POST["new_password"] ?? "";
    $confirmPassword = $_POST["confirm_password"] ?? "";

    if ($newPassword === "" || $confirmPassword === "") {
        $message = "Please fill in all fields.";
    } elseif ($newPassword !== $confirmPassword) {
        $message = "Passwords do not match.";
    } elseif (strlen($newPassword) < 8) {
        $message = "Password must be at least 8 characters.";
    } else {
        $userId = (int)$_SESSION["password_reset_user_id"];
        $username = (string)$_SESSION["password_reset_username"];
        $newHash = password_hash($newPassword, PASSWORD_DEFAULT);

        $stmt = $pdo->prepare('UPDATE public."Accounts" SET password = :password WHERE id = :id');
        $ok = $stmt->execute([
            'password' => $newHash,
            'id' => $userId
        ]);

        if ($ok) {
            markRecoveryKeyUsed($pdo, $userId);

            $newRecoveryKey = generateRecoveryKey();
            upsertRecoveryKey($pdo, $userId, $newRecoveryKey);

            logAttackEvent(
                "password_reset_success",
                "medium",
                "reset_password.php",
                [
                    "userId" => $userId,
                    "username" => $username
                ]
            );

            unset($_SESSION["password_reset_user_id"], $_SESSION["password_reset_username"]);

            forceRecoveryFileDownload($username, $newRecoveryKey);
        } else {
            $message = "Could not reset password.";
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
</head>
<body>
<div class="login-wrapper">
    <div class="login-box">
        <h1>Set New Password</h1>

        <?php if ($message): ?>
            <div class="login-error"><?= htmlspecialchars($message) ?></div>
        <?php endif; ?>

        <form method="post" action="">
            <div class="form-group">
                <label for="new_password">New Password</label>
                <input type="password" id="new_password" name="new_password" required>
            </div>

            <div class="form-group">
                <label for="confirm_password">Confirm Password</label>
                <input type="password" id="confirm_password" name="confirm_password" required>
            </div>

            <button type="submit" class="login-submit">Reset Password</button>
        </form>
    </div>
</div>
</body>
</html>
