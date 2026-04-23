<?php
session_start();

if (!isset($_SESSION["user_id"])) {
    header("Location: login.php");
    exit;
}

require_once __DIR__ . "/config.php";
require_once __DIR__ . "/fastapi_auth.php";

$result = null;
$error = "";
$passwordValue = "";

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $passwordValue = trim($_POST["password"] ?? "");

    if ($passwordValue === "") {
        $error = "Please enter a password.";
    } else {

        $endpoint = rtrim($fastApiBaseUrl, "/") . "/check-password";
        $idToken = getCloudRunIdToken($fastApiBaseUrl);
        
        $ch = curl_init($endpoint);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            "Content-Type: application/json",
            "Authorization: Bearer " . $idToken
        ]);
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode([
            "password" => $passwordValue
        ]));
        curl_setopt($ch, CURLOPT_TIMEOUT, 30);

        $response = curl_exec($ch);

        if (curl_errno($ch)) {
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
                    $error = "Prediction failed. HTTP Code: " . $httpCode . " Response: " . $response;
                }
            }
        }

        curl_close($ch);
    }
}

function getStrengthClass($className)
{
    $name = strtolower(trim((string)$className));

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
    <title>Password Checker | Optimsecurity</title>
    <link rel="stylesheet" href="password_checker.css">
    <link rel="icon" href="/favicon.ico" type="image/x-icon">

    <link rel="icon" type="image/png" sizes="32x32" href="/favicon-32x32.png">
    <link rel="icon" type="image/png" sizes="16x16" href="/favicon-16x16.png">

    <link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png">
    <link rel="manifest" href="/site.webmanifest">
</head>
<body class="checker-body">
    <div class="checker-shell">
        <aside class="checker-sidebar">
            <div class="checker-sidebar-title">
                <img src="optimsecuritylogo.png" alt="Optimsecurity" class="checker-sidebar-logo">
            </div>

            <nav class="checker-nav">
                <a href="homepage.php" class="checker-nav-item">Home</a>
                <a href="password_checker.php" class="checker-nav-item active">Password Check</a>
                <a href="password_generator.php" class="checker-nav-item">Password Gen</a>
                <a href="vault.php" class="checker-nav-item">Vault</a>
                <a href="phishing_toolkit.php" class="checker-nav-item">Phishing Toolkit</a>
                <a href="about.php" class="checker-nav-item">About Me</a>

                <div class="checker-sidebar-spacer"></div>

                <a href="security_settings.php" class="checker-nav-item">Security Settings</a>
                <a href="logout.php" class="checker-nav-item logout">Logout</a>
            </nav>
        </aside>

        <main class="checker-main">
            <section class="checker-hero-card">
                <div class="checker-badge">Password Checker</div>
                <h1>Check how secure your password really is</h1>
                <p>
                    This checker uses a CNN Machine Learning model to find out your password strength.
                </p>
            </section>

            <section class="checker-grid">
                <div class="checker-card">
                    <div class="checker-card-header">
                        <h2>Check a Password</h2>
                        <p>
                            Try examples like <strong>bettafish21</strong>, <strong>bettafi$21</strong>, or
                            <strong>bettafi$h@21</strong>.
                        </p>
                    </div>

                    <form method="POST" class="checker-form">
                        <div class="checker-form-group">
                            <label for="password">Password</label>
                            <input
                                type="text"
                                id="password"
                                name="password"
                                value="<?php echo htmlspecialchars($passwordValue); ?>"
                                placeholder="Type a password here"
                                required
                            >
                        </div>

                        <div class="checker-button-row">
                            <button type="submit" class="checker-btn">Check Password</button>
                        </div>
                    </form>

                    <?php if ($error !== ""): ?>
                        <div class="checker-message checker-error">
                            <?php echo htmlspecialchars($error); ?>
                        </div>
                    <?php endif; ?>
                </div>

                <div class="checker-card">
                    <div class="checker-card-header">
                        <h2>Result</h2>
                        <p>
                            Your CNN password rating is shown below.
                        </p>
                    </div>

                    <?php if ($result): ?>
                        <div class="checker-result-box">
                            <div class="checker-result-top">
                                <div>
                                    <div class="checker-result-title">Password Entered</div>
                                    <div class="checker-result-value">
                                        <?php echo htmlspecialchars($result["password"] ?? ""); ?>
                                    </div>
                                </div>

                                <span class="checker-pill <?php echo htmlspecialchars($strengthClass); ?>">
                                    <?php echo htmlspecialchars($ratingText); ?>
                                </span>
                            </div>

                            <div class="checker-stats-row">
                                <div class="checker-stat-box">
                                    <span class="checker-stat-label">Strength</span>
                                    <span class="checker-stat-value"><?php echo htmlspecialchars($ratingText); ?></span>
                                </div>

                                <div class="checker-stat-box">
                                    <span class="checker-stat-label">Password Length</span>
                                    <span class="checker-stat-value"><?php echo htmlspecialchars((string)$passwordLength); ?></span>
                                </div>
                            </div>
                        </div>
                    <?php else: ?>
                        <div class="checker-empty">
                            Submit a password to see the result here.
                        </div>
                    <?php endif; ?>
                </div>
            </section>

            <section class="checker-card">
                <div class="checker-card-header">
                    <h2>How This Checker Rates Passwords</h2>
                    <p>
                        These are the general ideas used when assigning a final rating.
                    </p>
                </div>

                <div class="checker-tips-grid">
                    <div class="checker-tip-box">
                        <h3>Weak</h3>
                        <p>
                            Common words, simple patterns, and obvious endings usually keep a password weak.
                        </p>
                    </div>

                    <div class="checker-tip-box">
                        <h3>Average</h3>
                        <p>
                            Better variation and length help, but the password may still be somewhat predictable.
                        </p>
                    </div>

                    <div class="checker-tip-box">
                        <h3>Strong</h3>
                        <p>
                            Strong passwords are longer, less obvious, and use a better mix of characters and structure.
                        </p>
                    </div>
                </div>
            </section>
        </main>
    </div>
</body>
</html>
