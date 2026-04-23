<?php
session_start();

header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Pragma: no-cache");
header("Expires: 0");

$username = $_SESSION["password_reset_username_done"] ?? "user";

if ($username === "user" && empty($_SESSION["password_reset_username_done"])) {
    header("Location: login.php");
    exit;
}

unset($_SESSION["user_id"], $_SESSION["user_username"], $_SESSION["user_name"], $_SESSION["logged_in"]);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Password Reset Complete | Optimsecurity</title>
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
            <h1>Password Reset Complete</h1>

            <p class="bottom-link" style="margin-bottom: 14px;">
                @<?= htmlspecialchars($username) ?>
            </p>

            <div class="login-success">
                Your password has been updated successfully.
            </div>

            <p class="bottom-link" style="margin-top: 14px; margin-bottom: 18px;">
                Please sign in again with your new password.
            </p>

            <form action="login.php" method="get">
                <button type="submit" class="login-submit">Back to Login</button>
            </form>
        </div>
    </div>

    <script>
        try {
            localStorage.clear();
            sessionStorage.clear();
        } catch (e) {}
    </script>
</body>
</html>
