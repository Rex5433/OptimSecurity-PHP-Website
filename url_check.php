<?php
session_start();

if (!isset($_SESSION["user_id"])) {
    header("Location: login.php");
    exit;
}

require_once "attack_helpers.php";

$result = "";
$severity = "low";

function looksMaliciousUrl(string $url): bool
{
    $patterns = [
        '/@/',
        '/bit\.ly|tinyurl|rb\.gy|goo\.su/i',
        '/login.*secure.*verify/i',
        '/free.*gift/i',
        '/paypal.*verify/i',
        '/microsoft.*reset.*account/i',
        '/google.*security.*alert/i',
        '/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/',
        '/xn--/i'
    ];

    foreach ($patterns as $pattern) {
        if (preg_match($pattern, $url)) {
            return true;
        }
    }

    return false;
}

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $url = trim($_POST["url"] ?? "");

    if (preg_match('/<script|javascript:|onerror=|union\s+select|drop\s+table/i', $url)) {
        logAttackEvent(
            "suspicious_request",
            "high",
            "url_check.php",
            [
                "reason" => "Suspicious URL input pattern"
            ]
        );
    }

    if ($url === "") {
        $result = "Please enter a URL.";
        $severity = "medium";
    } elseif (looksMaliciousUrl($url)) {
        $result = "This URL looks suspicious or potentially malicious.";
        $severity = "high";

        logAttackEvent(
            "malicious_url",
            "high",
            "url_check.php",
            [
                "url" => mb_substr($url, 0, 200)
            ]
        );
    } else {
        $result = "No strong malicious indicators found in this URL.";
        $severity = "low";
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>URL Check</title>
    <link rel="stylesheet" href="styles.css">
</head>
<body>
    <div class="tool-wrapper">
        <div class="tool-card">
            <h1>Malicious URL Check</h1>

            <form method="POST" action="">
                <input type="text" name="url" placeholder="Enter URL to analyze..." value="<?= htmlspecialchars($_POST["url"] ?? "") ?>">
                <button type="submit">Check URL</button>
            </form>

            <?php if ($result !== ""): ?>
                <div class="tool-result severity-<?= htmlspecialchars($severity) ?>">
                    <?= htmlspecialchars($result) ?>
                </div>
            <?php endif; ?>
        </div>
    </div>
</body>
</html>