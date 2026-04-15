<?php
include "db.php";

$message = "";
$success = "";

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $name = trim($_POST["name"] ?? "");
    $username = trim($_POST["username"] ?? "");
    $email = trim($_POST["email"] ?? "");
    $password_input = trim($_POST["password"] ?? "");
    $confirm_password = trim($_POST["confirm_password"] ?? "");

    if (empty($name) || empty($username) || empty($email) || empty($password_input) || empty($confirm_password)) {
        $message = "Please fill in all fields.";
    } elseif ($password_input !== $confirm_password) {
        $message = "Passwords do not match.";
    } elseif ($pdo) {
        $check_stmt = $pdo->prepare('SELECT id FROM "Accounts" WHERE username = :username OR email = :email');
        $check_stmt->execute([
            "username" => $username,
            "email" => $email
        ]);

        if ($check_stmt->fetch()) {
            $message = "Username or email already exists.";
        } else {
            $hashed_password = password_hash($password_input, PASSWORD_DEFAULT);

            $insert_stmt = $pdo->prepare('
                INSERT INTO "Accounts" (name, username, email, password)
                VALUES (:name, :username, :email, :password)
            ');

            $insert_stmt->execute([
                "name" => $name,
                "username" => $username,
                "email" => $email,
                "password" => $hashed_password
            ]);

            $success = "Account created successfully. You can now log in.";
        }
    } else {
        $message = "Database connection failed.";
    }
}
?>
<!DOCTYPE html>
<html>
<head>
    <title>Create Account</title>
    <link rel="stylesheet" href="styles.css">
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

            <form method="post">
                <div class="form-group">
                    <label>Name</label>
                    <input type="text" name="name" required>
                </div>

                <div class="form-group">
                    <label>Username</label>
                    <input type="text" name="username" required>
                </div>

                <div class="form-group">
                    <label>Email</label>
                    <input type="email" name="email" required>
                </div>

                <div class="form-group">
                    <label>Password</label>
                    <input type="password" name="password" required>
                </div>

                <div class="form-group">
                    <label>Confirm Password</label>
                    <input type="password" name="confirm_password" required>
                </div>

                <button type="submit" class="login-submit">Create Account</button>
            </form>

            <div class="divider"></div>

            <p class="bottom-link">
                <a href="login.php">Back to Login</a>
            </p>
        </div>
    </div>
</body>
</html>