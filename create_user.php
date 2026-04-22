<?php
include "db.php";
require_once __DIR__ . "/recovery_helpers.php";

$message = "";
$success = "";

$name = "";
$username = "";
$email = "";
$show_passwords = false;
$generatedRecoveryKey = "";

if ($_SERVER["REQUEST_METHOD"] == "POST") {

    $name = trim($_POST["name"] ?? "");
    $username = trim($_POST["username"] ?? "");
    $email = trim($_POST["email"] ?? "");
    $password_input = trim($_POST["password"] ?? "");
    $confirm_password = trim($_POST["confirm_password"] ?? "");
    $show_passwords = isset($_POST["show_passwords"]);

    if (
        empty($name) ||
        empty($username) ||
        empty($email) ||
        empty($password_input) ||
        empty($confirm_password)
    ) {
        $message = "Please fill in all fields.";
    } elseif (strlen($password_input) < 8) {
        $message = "Password must be at least 8 characters long.";
    } elseif (
        !preg_match('/[A-Z]/', $password_input) ||
        !preg_match('/[a-z]/', $password_input) ||
        !preg_match('/[0-9]/', $password_input) ||
        !preg_match('/[\W_]/', $password_input)
    ) {
        $message = "Password must contain an uppercase letter, lowercase letter, number, and special character.";
    } elseif ($password_input !== $confirm_password) {
        $message = "Passwords do not match.";
    } elseif ($pdo) {

        $check_stmt = $pdo->prepare('
            SELECT id
            FROM "Accounts"
            WHERE username = :username
            OR email = :email
        ');

        $check_stmt->execute([
            "username" => $username,
            "email" => $email
        ]);

        if ($check_stmt->fetch()) {
            $message = "Username or email already exists.";
        } else {
            try {
                $hashed_password = password_hash($password_input, PASSWORD_DEFAULT);

                $insert_stmt = $pdo->prepare('
                    INSERT INTO "Accounts" (name, username, email, password)
                    VALUES (:name, :username, :email, :password)
                    RETURNING id
                ');

                $insert_stmt->execute([
                    "name" => $name,
                    "username" => $username,
                    "email" => $email,
                    "password" => $hashed_password
                ]);

                $newUserId = $insert_stmt->fetchColumn();

                if (!$newUserId) {
                    $message = "Account created, but recovery key setup failed.";
                } else {
                    $generatedRecoveryKey = generateRecoveryKey();

                    if (!upsertRecoveryKey($pdo, (int) $newUserId, $generatedRecoveryKey)) {
                        $message = "Account created, but recovery key setup failed.";
                    } else {
                        $success = "Account created successfully. Save your recovery key now.";
                    }
                }
            } catch (Throwable $e) {
                $message = "Could not create account right now.";
            }
        }

    } else {
        $message = "Database connection failed.";
    }
}
?>
<!DOCTYPE html>
<html>
<head>
    <title>Create Account | Optimsecurity</title>
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
            <h1>Create Account</h1>

            <?php if ($message): ?>
                <div class="login-error"><?= htmlspecialchars($message) ?></div>
            <?php endif; ?>

            <?php if ($success): ?>
                <div class="login-success"><?= htmlspecialchars($success) ?></div>
            <?php endif; ?>

            <?php if ($generatedRecoveryKey !== ""): ?>
                <div class="recovery-key-box">
                    <?= htmlspecialchars($generatedRecoveryKey) ?>
                </div>

                <div class="recovery-note">
                    Save this recovery key somewhere secure. It will only be shown once.
                </div>

                <div class="divider"></div>

                <p class="bottom-link">
                    <a href="login.php">Continue to Login</a>
                </p>
            <?php else: ?>
                <form method="post">
                    <div class="form-group">
                        <label>Name</label>
                        <input type="text" name="name" required value="<?= htmlspecialchars($name) ?>">
                    </div>

                    <div class="form-group">
                        <label>Username</label>
                        <input type="text" name="username" required value="<?= htmlspecialchars($username) ?>">
                    </div>

                    <div class="form-group">
                        <label>Email</label>
                        <input type="email" name="email" required value="<?= htmlspecialchars($email) ?>">
                    </div>

                    <div class="form-group">
                        <label>Password</label>
                        <input
                            type="<?= $show_passwords ? 'text' : 'password' ?>"
                            name="password"
                            id="password"
                            required
                        >
                    </div>

                    <div class="form-group">
                        <label>Confirm Password</label>
                        <input
                            type="<?= $show_passwords ? 'text' : 'password' ?>"
                            name="confirm_password"
                            id="confirm_password"
                            required
                        >
                    </div>

                    <div class="options-row create-account-options">
                        <label class="checkbox-container">
                            <input
                                type="checkbox"
                                name="show_passwords"
                                id="show_passwords"
                                onclick="togglePasswords()"
                                <?= $show_passwords ? 'checked' : '' ?>
                            >
                            <span>Show Passwords</span>
                        </label>
                    </div>

                    <button type="submit" class="login-submit">Create Account</button>
                </form>

                <div class="divider"></div>

                <p class="bottom-link">
                    <a href="login.php">Back to Login</a>
                </p>
            <?php endif; ?>
        </div>
    </div>

    <script>
        function togglePasswords() {
            const password = document.getElementById("password");
            const confirmPassword = document.getElementById("confirm_password");
            const checkbox = document.getElementById("show_passwords");

            if (checkbox.checked) {
                password.type = "text";
                confirmPassword.type = "text";
            } else {
                password.type = "password";
                confirmPassword.type = "password";
            }
        }
    </script>
</body>
</html>
