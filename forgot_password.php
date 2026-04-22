<?php
session_start();

include "db.php";
require_once __DIR__ . "/recovery_helpers.php";
require_once __DIR__ . "/attack_helpers.php";

$message = "";
$success = false;

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $username = trim($_POST["username"] ?? "");
    $recoveryKey = trim($_POST["recovery_key"] ?? "");

    if ($username === "" || $recoveryKey === "") {
        $message = "Please fill in all fields.";
    } elseif (!$pdo) {
        $message = "Database connection failed.";
    } else {
        $row = getRecoveryRowByUsername($pdo, $username);

        if ($row && verifyRecoveryKey($recoveryKey, (string)$row["recovery_key_hash"])) {
            $_SESSION["password_reset_user_id"] = (int)$row["id"];
            $_SESSION["password_reset_username"] = (string)$row["username"];

            logAttackEvent(
                "recovery_key_verified",
                "medium",
                "forgot_password.php",
                [
                    "userId" => (int)$row["id"],
                    "username" => (string)$row["username"]
                ]
            );

            header("Location: reset_password.php");
            exit;
        } else {
            $message = "Invalid username or recovery key.";

            logAttackEvent(
                "failed_recovery_attempt",
                "high",
                "forgot_password.php",
                [
                    "username" => $username,
                    "reason" => "Invalid recovery key"
                ]
            );
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Forgot Password | Optimsecurity</title>
    <link rel="stylesheet" href="styles.css">
</head>
<body>
<div class="login-wrapper">
    <div class="login-box">
        <h1>Recovery Key Reset</h1>

        <?php if ($message): ?>
            <div class="login-error"><?= htmlspecialchars($message) ?></div>
        <?php endif; ?>

        <form method="post" action="">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" required>
            </div>

            <div class="form-group">
                <label for="recovery_key">Recovery Key</label>
                <input type="text" id="recovery_key" name="recovery_key" placeholder="XXXX-XXXX-XXXX-XXXX-XXXX" required>
            </div>

            <button type="submit" class="login-submit">Verify Recovery Key</button>
        </form>

        <div class="divider"></div>
        <p class="bottom-link"><a href="login.php">Back to Login</a></p>
    </div>
</div>
</body>
</html>
