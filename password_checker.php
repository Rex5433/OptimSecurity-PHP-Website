<?php
declare(strict_types=1);

session_start();

header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Cache-Control: post-check=0, pre-check=0", false);
header("Pragma: no-cache");
header("Expires: 0");

if (!isset($_SESSION["user_id"])) {
    header("Location: /Login/login.php");
    exit;
}

require_once __DIR__ . "/config.php";
require_once __DIR__ . "/db.php";
require_once __DIR__ . "/fastapi_auth.php";

$result = null;
$error = "";
$passwordValue = "";

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $passwordValue = trim((string)($_POST["password"] ?? ""));

    if ($passwordValue === "") {
        $error = "Please enter a password.";
    } elseif ($fastApiBaseUrl === "") {
        $error = "FastAPI service URL is not configured.";
    } else {
        try {
            $payload = json_encode([
                "password" => $passwordValue
            ], JSON_THROW_ON_ERROR);

            $endpoint = rtrim($fastApiBaseUrl, "/") . "/check-password";
            $idToken = getCloudRunIdToken($fastApiBaseUrl);

            $ch = curl_init($endpoint);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_HTTPHEADER, [
                "Content-Type: application/json",
                "Authorization: Bearer " . $idToken
            ]);
            curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
            curl_setopt($ch, CURLOPT_TIMEOUT, 30);

            $response = curl_exec($ch);

            if ($response === false) {
                $error = "Connection error: " . curl_error($ch);
            } else {
                $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
                $data = json_decode($response, true);

                if ($httpCode === 200 && is_array($data) && !empty($data["success"])) {
                    $result = $data;
                } else {
                    $apiMessage = "";

                    if (is_array($data)) {
                        $apiMessage = $data["message"] ?? ($data["detail"] ?? "");
                    }

                    if ($apiMessage !== "") {
                        $error = $apiMessage;
                    } else {
                        $error = "Prediction failed. HTTP Code: " . $httpCode;
                    }
                }
            }

            curl_close($ch);
        } catch (Throwable $e) {
            error_log("Password checker proxy error: " . $e->getMessage());
            $error = "Password checking service is unavailable.";
        }
    }
}

function getStrengthClass(string $className): string
{
    $name = strtolower(trim($className));

    if ($name === "very weak" || $name === "weak") {
        return "weak";
    }

    if ($name === "average") {
        return "medium";
    }

    if ($name === "strong" || $name === "very strong") {
        return "strong";
    }

    return "medium";
}

$ratingText = "";
$strengthClass = "medium";
$passwordLength = 0;

if ($result) {
    $ratingText = (string)($result["strength"] ?? "Unknown");
    $strengthClass = getStrengthClass($ratingText);
    $passwordLength = strlen((string)($result["password"] ?? $passwordValue));
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Password Checker | Security Dashboard</title>
    <link rel="stylesheet" href="password_checker.css">
</head>
<body>
    <div class="page-wrapper">
        <aside class="sidebar">
            <h2>Dashboard</h2>
            <nav class="sidebar-nav">
                <a href="homepage.php">Home</a>
                <a href="password_checker.php" class="active">Password Check</a>
                <a href="password_generator.php">Password Gen</a>
                <a href="vault.php">Vault</a>
                <a href="phishing_toolkit.php">Phishing Toolkit</a>
                <a href="about.php">About Me</a>
            </nav>

            <div class="sidebar-bottom">
                <a href="security_setting.php">Security Settings</a>
                <a href="logout.php">Logout</a>
            </div>
        </aside>

        <main class="main-content">
            <section class="checker-hero">
                <div class="checker-hero-text">
                    <p class="eyebrow">Password Checker</p>
                    <h1>Check how secure your password really is</h1>
                    <p>
                        This checker uses a CNN Machine Learning model to find out your password strength.
                    </p>
                </div>
            </section>

            <section class="checker-card">
                <div class="card-header">
                    <h2>Check a Password</h2>
                    <p>Try examples like bettafish21, bettafi$21, or bettafi$h@21.</p>
                </div>

                <form method="POST" class="checker-form">
                    <label for="password">Password</label>
                    <input
                        type="text"
                        id="password"
                        name="password"
                        value="<?= htmlspecialchars($passwordValue) ?>"
                        placeholder="Enter a password"
                        autocomplete="off"
                    >
                    <button type="submit">Check Password</button>
                </form>

                <?php if ($error !== ""): ?>
                    <div class="message error-message">
                        <?= htmlspecialchars($error) ?>
                    </div>
                <?php endif; ?>
            </section>

            <section class="result-card">
                <div class="card-header">
                    <h2>Result</h2>
                    <p>Your CNN password rating is shown below.</p>
                </div>

                <?php if ($result): ?>
                    <div class="result-grid">
                        <div class="result-box">
                            <span class="result-label">Password Entered</span>
                            <span class="result-value"><?= htmlspecialchars($passwordValue) ?></span>
                        </div>

                        <div class="result-box">
                            <span class="result-label">Strength</span>
                            <span class="result-value strength-pill <?= htmlspecialchars($strengthClass) ?>">
                                <?= htmlspecialchars($ratingText) ?>
                            </span>
                        </div>

                        <div class="result-box">
                            <span class="result-label">Password Length</span>
                            <span class="result-value"><?= (int)$passwordLength ?></span>
                        </div>
                    </div>
                <?php else: ?>
                    <div class="empty-state">
                        Submit a password to see the result here.
                    </div>
                <?php endif; ?>
            </section>

            <section class="info-card">
                <div class="card-header">
                    <h2>How This Checker Rates Passwords</h2>
                    <p>These are the general ideas used when assigning a final rating.</p>
                </div>

                <div class="info-grid">
                    <div class="info-box">
                        <h3>Weak</h3>
                        <p>Common words, simple patterns, and obvious endings usually keep a password weak.</p>
                    </div>

                    <div class="info-box">
                        <h3>Average</h3>
                        <p>Better variation and length help, but the password may still be somewhat predictable.</p>
                    </div>

                    <div class="info-box">
                        <h3>Strong</h3>
                        <p>Strong passwords are longer, less obvious, and use a better mix of characters and structure.</p>
                    </div>
                </div>
            </section>
        </main>
    </div>
</body>
</html>
