<?php
session_start();

header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Cache-Control: post-check=0, pre-check=0", false);
header("Pragma: no-cache");
header("Expires: 0");

if (!isset($_SESSION["user_id"])) {
    header("Location: login.php");
    exit;
}

require_once __DIR__ . "/attack_helpers.php";
require_once __DIR__ . "/db.php";

$userId = (int) ($_SESSION["user_id"] ?? 0);
$name = $_SESSION["user_name"] ?? "User";

$kevUrl = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
$advisoriesUrl = "https://www.cisa.gov/news-events/cybersecurity-advisories";

$recentVulns = [];
$newsItems = [];
$feedError = "";
$feedOnline = false;
$advisoryOnline = false;

function safeText($value, $default = "N/A")
{
    $value = trim((string) ($value ?? ""));
    return $value !== "" ? htmlspecialchars($value) : $default;
}

function getThreatScore($count)
{
    if ($count >= 8) {
        return "Critical";
    }
    if ($count >= 5) {
        return "High";
    }
    if ($count >= 3) {
        return "Elevated";
    }
    return "Low";
}

function getActionLabel($requiredAction)
{
    $action = strtolower((string) $requiredAction);

    if (str_contains($action, "patch") || str_contains($action, "update")) {
        return "Patch Available";
    }
    if (str_contains($action, "mitig")) {
        return "Mitigation Needed";
    }
    if (str_contains($action, "disconnect") || str_contains($action, "remove")) {
        return "Immediate Action";
    }

    return "Review";
}

function fetchUrl($url)
{
    $context = stream_context_create([
        "http" => [
            "method" => "GET",
            "timeout" => 10,
            "header" => "User-Agent: SecurityDashboard/1.0\r\n"
        ]
    ]);

    return @file_get_contents($url, false, $context);
}

function normalizeEventType(string $eventType): string
{
    $value = strtolower(trim($eventType));

    if (
        str_contains($value, "fail") ||
        str_contains($value, "invalid") ||
        str_contains($value, "denied") ||
        str_contains($value, "blocked") ||
        str_contains($value, "error")
    ) {
        return "failed";
    }

    if (
        str_contains($value, "success") ||
        str_contains($value, "login") ||
        str_contains($value, "signed in") ||
        str_contains($value, "authenticated")
    ) {
        return "success";
    }

    return "success";
}

function formatEventLabel(string $eventType): string
{
    return normalizeEventType($eventType) === "failed"
        ? "Failed Login Attempt"
        : "Successful Login";
}

function formatLocationText(array $row): string
{
    $parts = [];

    $city = trim((string) ($row["city"] ?? ""));
    $region = trim((string) ($row["region"] ?? ""));
    $country = trim((string) ($row["country"] ?? ""));
    $location = trim((string) ($row["location"] ?? ""));

    if ($city !== "") {
        $parts[] = $city;
    }
    if ($region !== "") {
        $parts[] = $region;
    }

    if (!empty($parts)) {
        return implode(", ", $parts);
    }

    if ($country !== "") {
        return $country;
    }

    if ($location !== "") {
        return $location;
    }

    return "Unknown Location";
}

function parseDeviceLabel(string $userAgent): string
{
    $ua = strtolower($userAgent);

    if ($ua === "") {
        return "Unknown Device";
    }

    if (str_contains($ua, "edg")) {
        return "Edge Browser";
    }
    if (str_contains($ua, "chrome") && !str_contains($ua, "edg")) {
        return "Chrome Browser";
    }
    if (str_contains($ua, "firefox")) {
        return "Firefox Browser";
    }
    if (str_contains($ua, "safari") && !str_contains($ua, "chrome")) {
        return "Safari Browser";
    }
    if (str_contains($ua, "android")) {
        return "Android Device";
    }
    if (str_contains($ua, "iphone") || str_contains($ua, "ipad") || str_contains($ua, "ios")) {
        return "Apple Mobile Device";
    }
    if (str_contains($ua, "windows")) {
        return "Windows Device";
    }
    if (str_contains($ua, "mac")) {
        return "Mac Device";
    }
    if (str_contains($ua, "linux")) {
        return "Linux Device";
    }

    return "Web Browser";
}

function buildLiveActivity(PDO $pdo, int $userId): array
{
    $successSeries = [];
    $failedSeries = [];
    $labels = [];
    $dates = [];

    $todaySuccess = 0;
    $todayFailed = 0;
    $weekSuccess = 0;
    $weekFailed = 0;

    for ($i = 6; $i >= 0; $i--) {
        $dayTs = strtotime("-$i days");
        $dayStart = date("Y-m-d 00:00:00", $dayTs);
        $dayEnd = date("Y-m-d 23:59:59", $dayTs);

        $stmt = $pdo->prepare("
            SELECT event_type
            FROM public.login_activity
            WHERE user_id = ?
              AND created_at BETWEEN ? AND ?
            ORDER BY created_at ASC
        ");
        $stmt->execute([$userId, $dayStart, $dayEnd]);

        $successCount = 0;
        $failedCount = 0;

        while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
            $normalized = normalizeEventType((string) ($row["event_type"] ?? ""));
            if ($normalized === "failed") {
                $failedCount++;
            } else {
                $successCount++;
            }
        }

        $successSeries[] = $successCount;
        $failedSeries[] = $failedCount;
        $labels[] = date("D", strtotime($dayStart));
        $dates[] = date("M j", strtotime($dayStart));

        $weekSuccess += $successCount;
        $weekFailed += $failedCount;

        if ($i === 0) {
            $todaySuccess = $successCount;
            $todayFailed = $failedCount;
        }
    }

    $totalAttempts = $weekSuccess + $weekFailed;
    $successRate = $totalAttempts > 0 ? (int) round(($weekSuccess / $totalAttempts) * 100) : 0;

    $recentStmt = $pdo->prepare("
        SELECT created_at, event_type, ip_address, location, city, region, country, user_agent
        FROM public.login_activity
        WHERE user_id = ?
        ORDER BY created_at DESC
        LIMIT 5
    ");
    $recentStmt->execute([$userId]);

    $recentActivity = [];
    while ($row = $recentStmt->fetch(PDO::FETCH_ASSOC)) {
        $recentActivity[] = [
            "status" => normalizeEventType((string) ($row["event_type"] ?? "")),
            "label" => formatEventLabel((string) ($row["event_type"] ?? "")),
            "date" => !empty($row["created_at"]) ? date("D M j, g:i A", strtotime((string) $row["created_at"])) : "Unknown Time",
            "location" => formatLocationText($row),
            "device" => parseDeviceLabel((string) ($row["user_agent"] ?? "")),
            "ip" => trim((string) ($row["ip_address"] ?? "")) !== "" ? (string) $row["ip_address"] : "Unknown IP"
        ];
    }

    $latest = $recentActivity[0] ?? null;

    return [
        "successSeries" => $successSeries,
        "failedSeries" => $failedSeries,
        "labels" => $labels,
        "dates" => $dates,
        "todaySuccess" => $todaySuccess,
        "todayFailed" => $todayFailed,
        "weekSuccess" => $weekSuccess,
        "weekFailed" => $weekFailed,
        "totalAttempts" => $totalAttempts,
        "successRate" => $successRate,
        "recentActivity" => $recentActivity,
        "latestActivity" => $latest
    ];
}

$rawKev = fetchUrl($kevUrl);

if ($rawKev !== false) {
    $data = json_decode($rawKev, true);

    if (isset($data["vulnerabilities"]) && is_array($data["vulnerabilities"])) {
        $feedOnline = true;
        $vulns = $data["vulnerabilities"];

        usort($vulns, function ($a, $b) {
            $dateA = strtotime($a["dateAdded"] ?? "1970-01-01");
            $dateB = strtotime($b["dateAdded"] ?? "1970-01-01");
            return $dateB <=> $dateA;
        });

        $recentVulns = array_slice($vulns, 0, 4);
    } else {
        $feedError .= "KEV feed format was unexpected. ";
    }
} else {
    $feedError .= "Unable to load CISA KEV feed. ";
}

$rawAdvisories = fetchUrl($advisoriesUrl);

if ($rawAdvisories !== false) {
    $advisoryOnline = true;

    preg_match_all('/<a[^>]*href="([^"]+)"[^>]*>(.*?)<\/a>/is', $rawAdvisories, $matches, PREG_SET_ORDER);

    foreach ($matches as $match) {
        $href = html_entity_decode($match[1], ENT_QUOTES | ENT_HTML5);
        $title = trim(strip_tags($match[2]));
        $dateText = "";

        if (
            $title !== "" &&
            strlen($title) > 18 &&
            (
                str_contains($href, "/news-events/alerts/") ||
                str_contains($href, "/news-events/cybersecurity-advisories/")
            )
        ) {
            if (!str_starts_with($href, "http")) {
                $href = "https://www.cisa.gov" . $href;
            }

            if (preg_match('/(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\.? \d{1,2}, \d{4}/i', strip_tags($match[2]), $dateMatch)) {
                $dateText = $dateMatch[0];
            }

            $newsItems[] = [
                "title" => $title,
                "summary" => "Live update from CISA Cybersecurity Alerts & Advisories.",
                "meta" => "Source: CISA",
                "date" => $dateText,
                "link" => $href
            ];
        }

        if (count($newsItems) >= 3) {
            break;
        }
    }

    $newsItems = array_values(array_unique($newsItems, SORT_REGULAR));
} else {
    $feedError .= "Unable to load CISA advisories page. ";
}

if (empty($recentVulns)) {
    $recentVulns = [
        [
            "vendorProject" => "Feed Status",
            "product" => "Unavailable",
            "shortDescription" => "Live vulnerability data could not be loaded.",
            "requiredAction" => "Retry later",
            "dateAdded" => date("Y-m-d")
        ]
    ];
}

if (empty($newsItems)) {
    $newsItems = [
        [
            "title" => "Live security updates unavailable",
            "summary" => "Could not load titled security updates right now.",
            "meta" => "Fallback mode",
            "date" => date("Y-m-d"),
            "link" => "#"
        ]
    ];
}

$liveActivity = buildLiveActivity($pdo, $userId);

$alertCount = count($recentVulns);
$threatScore = getThreatScore($alertCount);
$passwordHealth = "Strong";
$feedStatusText = ($feedOnline || $advisoryOnline) ? "Live Feed Online" : "Feed Offline";
$liveStatusClass = ($feedOnline || $advisoryOnline) ? "live-status-bar" : "live-status-bar offline";
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Homepage | Security Dashboard</title>
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="homepage.css">
</head>
<body class="dashboard-body">
    <div class="dash-shell">
        <aside class="dash-sidebar">
            <div class="dash-sidebar-title">Dashboard</div>

            <nav class="dash-nav">
                <a class="dash-nav-item active" href="homepage.php" data-tool="home">Home</a>
                <a class="dash-nav-item" href="password_checker.php" data-tool="password">Password Check</a>
                <a class="dash-nav-item" href="password_generator.php" data-tool="password">Password Gen</a>
                <a class="dash-nav-item" href="vault.php" data-tool="vault">Vault</a>
                <a class="dash-nav-item" href="phishing_toolkit.php" data-tool="phishing">Phishing Toolkit</a>
                <a class="dash-nav-item" href="about.php" data-tool="home">About Me</a>
            </nav>

            <div class="dash-sidebar-spacer"></div>

            <a class="dash-nav-item" href="security_settings.php" data-tool="home">Security Settings</a>
            <a class="dash-nav-item logout" href="logout.php">Logout</a>
        </aside>

        <main class="dash-main">
            <section class="dash-hero">
                <div class="dash-title-box">
                    <span class="dash-badge">Security Overview</span>
                    <h1>Security Dashboard</h1>
                    <p>Welcome back, <?= htmlspecialchars($name) ?></p>
                </div>
            </section>

            <section class="dash-grid-top">
                <div class="dash-card">
                    <div class="card-header">
                        <h2>Recent Security Updates</h2>
                    </div>

                    <div class="card-actions">
                        <div class="<?= $liveStatusClass ?>" id="liveStatusBar">
                            <span class="live-status-left">
                                <span class="status-dot"></span>
                                <span id="feedStatusText"><?= htmlspecialchars($feedStatusText) ?></span>
                            </span>

                            <span class="live-status-divider"></span>

                            <span class="live-status-right" id="liveUpdateLabel">Waiting for refresh...</span>
                        </div>

                        <button class="refresh-btn" id="manualRefreshBtn" type="button">Refresh Feed</button>
                    </div>

                    <div class="feed-warning<?= trim($feedError) === '' ? ' hidden-warning' : '' ?>" id="feedWarning">
                        <?= htmlspecialchars(trim($feedError)) ?>
                    </div>

                    <div class="news-list" id="newsList">
                        <?php foreach ($newsItems as $item): ?>
                            <a class="news-item live-news news-link-card" href="<?= htmlspecialchars($item["link"]) ?>" target="_blank" rel="noopener noreferrer">
                                <div class="news-head"><?= safeText($item["title"]) ?></div>
                                <div class="news-sub"><?= safeText($item["summary"]) ?></div>
                                <div class="news-meta">
                                    <?= safeText($item["meta"]) ?>
                                    <?php if (!empty($item["date"])): ?>
                                        <span class="news-date">• <?= safeText($item["date"]) ?></span>
                                    <?php endif; ?>
                                </div>
                            </a>
                        <?php endforeach; ?>
                    </div>
                </div>

                <div class="dash-card live-activity-card">
                    <div class="live-activity-header">
                        <div>
                            <h2>Live Activity</h2>
                            <p>Your login activity overview</p>
                        </div>
                    </div>

                    <div class="live-activity-chart-shell">
                        <div class="live-activity-chart-top">
                            <span>This Week</span>
                            <span>Click a bar for details</span>
                        </div>

                        <div class="live-activity-chart" id="liveActivityChart"></div>

                        <div class="live-activity-legend">
                            <span class="legend-item">
                                <span class="legend-dot legend-success"></span>
                                Successful
                            </span>
                            <span class="legend-item">
                                <span class="legend-dot legend-failed"></span>
                                Failed
                            </span>
                        </div>
                    </div>

                    <div class="live-stat-grid">
                        <div class="live-stat-box">
                            <div class="live-stat-title">TODAY</div>
                            <div class="live-stat-main success-text" id="todaySuccessCount"><?= (int) $liveActivity["todaySuccess"] ?></div>
                            <div class="live-stat-sub">Successful Logins</div>
                            <div class="live-stat-divider"></div>
                            <div class="live-stat-secondary failed-text" id="todayFailedCount"><?= (int) $liveActivity["todayFailed"] ?></div>
                            <div class="live-stat-sub">Failed Attempts</div>
                        </div>

                        <div class="live-stat-box">
                            <div class="live-stat-title">THIS WEEK</div>
                            <div class="live-stat-main success-text" id="weekSuccessCount"><?= (int) $liveActivity["weekSuccess"] ?></div>
                            <div class="live-stat-sub">Successful Logins</div>
                            <div class="live-stat-divider"></div>
                            <div class="live-stat-secondary failed-text" id="weekFailedCount"><?= (int) $liveActivity["weekFailed"] ?></div>
                            <div class="live-stat-sub">Failed Attempts</div>
                        </div>

                        <div class="live-stat-box">
                            <div class="live-stat-title">SUCCESS RATE</div>
                            <div class="live-stat-main success-text" id="successRateValue"><?= (int) $liveActivity["successRate"] ?>%</div>
                            <div class="live-stat-sub">Success over this week</div>
                        </div>

                        <div class="live-stat-box">
                            <div class="live-stat-title">TOTAL ATTEMPTS</div>
                            <div class="live-stat-main neutral-text" id="totalAttemptsValue"><?= (int) $liveActivity["totalAttempts"] ?></div>
                            <div class="live-stat-sub">This week</div>
                        </div>
                    </div>

                    <div class="recent-activity-box">
                        <div class="recent-activity-top">
                            <h3>Recent Login Activity</h3>
                            <button type="button" class="recent-activity-btn">View All Activity</button>
                        </div>

                        <div class="recent-activity-list" id="recentActivityList">
                            <?php foreach ($liveActivity["recentActivity"] as $activity): ?>
                                <div class="recent-activity-row">
                                    <div class="recent-activity-status <?= $activity["status"] === "failed" ? "status-failed" : "status-success" ?>">
                                        <?= $activity["status"] === "failed" ? "✕" : "✓" ?>
                                    </div>

                                    <div class="recent-activity-main">
                                        <div class="recent-activity-label <?= $activity["status"] === "failed" ? "failed-text" : "" ?>">
                                            <?= htmlspecialchars($activity["label"]) ?>
                                        </div>
                                        <div class="recent-activity-date"><?= htmlspecialchars($activity["date"]) ?></div>
                                    </div>

                                    <div class="recent-activity-meta"><?= htmlspecialchars($activity["location"]) ?></div>
                                    <div class="recent-activity-meta"><?= htmlspecialchars($activity["device"]) ?></div>
                                    <div class="recent-activity-ip"><?= htmlspecialchars($activity["ip"]) ?></div>
                                </div>
                            <?php endforeach; ?>
                        </div>
                    </div>
                </div>
            </section>

            <section class="dash-grid-bottom">
                <div class="dash-card">
                    <div class="card-header">
                        <h2>Recent Vulnerabilities</h2>
                    </div>

                    <div class="dash-table-like" id="vulnList">
                        <?php foreach ($recentVulns as $vuln): ?>
                            <?php
                            $vendor = trim((string) ($vuln["vendorProject"] ?? ""));
                            $product = trim((string) ($vuln["product"] ?? ""));
                            $summary = trim((string) ($vuln["shortDescription"] ?? "No description available."));
                            $actionLabel = getActionLabel($vuln["requiredAction"] ?? "");
                            $dateAdded = trim((string) ($vuln["dateAdded"] ?? ""));

                            $displayTitle = ($vendor !== "" && $product !== "")
                                ? $vendor . " / " . $product
                                : (($vendor !== "") ? $vendor : (($product !== "") ? $product : "Unnamed Vulnerability"));
                            ?>
                            <div class="dash-row no-cve-row">
                                <span class="row-dot"></span>

                                <div class="row-main vuln-main">
                                    <div class="vuln-title"><?= htmlspecialchars($displayTitle) ?></div>
                                    <div class="vuln-summary"><?= htmlspecialchars($summary) ?></div>

                                    <?php if ($dateAdded !== ""): ?>
                                        <div class="vuln-meta">Added: <?= htmlspecialchars($dateAdded) ?></div>
                                    <?php endif; ?>
                                </div>

                                <div class="row-side vuln-status-wrap">
                                    <span class="severity-pill sev-default">Known Exploited</span>
                                </div>

                                <div class="row-side vuln-action-wrap">
                                    <span class="vuln-action"><?= htmlspecialchars($actionLabel) ?></span>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    </div>
                </div>

                <div class="dash-card quick-tips-card">
                    <div class="card-header quick-tips-header">
                        <div class="quick-tips-heading">
                            <h2>Quick Tips</h2>
                            <p class="quick-tips-subtext">
                                Smart security guidance based on your activity
                            </p>
                        </div>
                    </div>

                    <div class="quick-tips-bar">
                        <div class="tips-search-wrapper">
                            <input type="text" id="tipsSearch" class="tips-search-input" placeholder="Search tips like MFA, phishing, passwords...">
                        </div>

                        <button type="button" class="refresh-btn" id="shuffleTipsBtn">
                            New Tips
                        </button>
                    </div>

                    <div class="tips-list" id="tipsList"></div>
                    <div class="empty-state hidden-warning" id="tipsEmptyState">
                        No tips matched your search.
                    </div>
                </div>
            </section>
        </main>
    </div>

    <script>
        const newsList = document.getElementById("newsList");
        const vulnList = document.getElementById("vulnList");
        const liveStatusBar = document.getElementById("liveStatusBar");
        const feedStatusText = document.getElementById("feedStatusText");
        const feedWarning = document.getElementById("feedWarning");
        const liveUpdateLabel = document.getElementById("liveUpdateLabel");
        const manualRefreshBtn = document.getElementById("manualRefreshBtn");

        const liveActivityChart = document.getElementById("liveActivityChart");
        const todaySuccessCount = document.getElementById("todaySuccessCount");
        const todayFailedCount = document.getElementById("todayFailedCount");
        const weekSuccessCount = document.getElementById("weekSuccessCount");
        const weekFailedCount = document.getElementById("weekFailedCount");
        const successRateValue = document.getElementById("successRateValue");
        const totalAttemptsValue = document.getElementById("totalAttemptsValue");
        const recentActivityList = document.getElementById("recentActivityList");

        const tipsList = document.getElementById("tipsList");
        const tipsSearch = document.getElementById("tipsSearch");
        const shuffleTipsBtn = document.getElementById("shuffleTipsBtn");
        const tipsEmptyState = document.getElementById("tipsEmptyState");

        function escapeHtml(text) {
            const div = document.createElement("div");
            div.textContent = text ?? "";
            return div.innerHTML;
        }

        function renderNews(items) {
            newsList.innerHTML = "";

            items.forEach(item => {
                const a = document.createElement("a");
                a.className = "news-item live-news news-link-card";
                a.href = item.link || "#";
                a.target = "_blank";
                a.rel = "noopener noreferrer";

                const dateHtml = item.date
                    ? `<span class="news-date">• ${escapeHtml(item.date)}</span>`
                    : "";

                a.innerHTML = `
                    <div class="news-head">${escapeHtml(item.title || "Untitled Update")}</div>
                    <div class="news-sub">${escapeHtml(item.summary || "")}</div>
                    <div class="news-meta">${escapeHtml(item.meta || "")} ${dateHtml}</div>
                `;

                newsList.appendChild(a);
            });
        }

        function renderVulns(items) {
            vulnList.innerHTML = "";

            items.forEach(item => {
                const row = document.createElement("div");
                row.className = "dash-row no-cve-row";

                const metaHtml = item.dateAdded
                    ? `<div class="vuln-meta">Added: ${escapeHtml(item.dateAdded)}</div>`
                    : "";

                row.innerHTML = `
                    <span class="row-dot"></span>
                    <div class="row-main vuln-main">
                        <div class="vuln-title">${escapeHtml(item.title || "Unnamed Vulnerability")}</div>
                        <div class="vuln-summary">${escapeHtml(item.summary || "No description available.")}</div>
                        ${metaHtml}
                    </div>
                    <div class="row-side vuln-status-wrap">
                        <span class="severity-pill sev-default">Known Exploited</span>
                    </div>
                    <div class="row-side vuln-action-wrap">
                        <span class="vuln-action">${escapeHtml(item.action || "Review")}</span>
                    </div>
                `;

                vulnList.appendChild(row);
            });
        }

        function renderLiveActivityChart(successSeries, failedSeries, labels, dates) {
            const safeSuccess = Array.isArray(successSeries) && successSeries.length === 7
                ? successSeries.map(v => Number(v) || 0)
                : [0, 0, 0, 0, 0, 0, 0];

            const safeFailed = Array.isArray(failedSeries) && failedSeries.length === 7
                ? failedSeries.map(v => Number(v) || 0)
                : [0, 0, 0, 0, 0, 0, 0];

            const safeLabels = Array.isArray(labels) && labels.length === 7
                ? labels
                : ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];

            const safeDates = Array.isArray(dates) && dates.length === 7
                ? dates
                : ["", "", "", "", "", "", ""];

            const maxValue = Math.max(...safeSuccess, ...safeFailed, 1);

            liveActivityChart.innerHTML = `
                <div class="live-chart-grid-lines">
                    <span>5</span>
                    <span>4</span>
                    <span>3</span>
                    <span>2</span>
                    <span>1</span>
                    <span>0</span>
                </div>
                <div class="live-chart-columns"></div>
            `;

            const columns = liveActivityChart.querySelector(".live-chart-columns");

            safeLabels.forEach((label, index) => {
                const successValue = safeSuccess[index];
                const failedValue = safeFailed[index];

                const successHeight = Math.max((successValue / maxValue) * 100, successValue > 0 ? 8 : 0);
                const failedHeight = Math.max((failedValue / maxValue) * 100, failedValue > 0 ? 8 : 0);

                const col = document.createElement("div");
                col.className = "live-chart-col";

                col.innerHTML = `
                    <div class="live-chart-bars">
                        <div class="live-bar-wrap">
                            <div class="live-bar-value success-text">${successValue}</div>
                            <div class="live-bar live-bar-success" style="height:${successHeight}%"></div>
                        </div>
                        <div class="live-bar-wrap">
                            <div class="live-bar-value failed-text">${failedValue}</div>
                            <div class="live-bar live-bar-failed" style="height:${failedHeight}%"></div>
                        </div>
                    </div>
                    <div class="live-chart-day">${escapeHtml(label)}</div>
                    <div class="live-chart-date">${escapeHtml(safeDates[index])}</div>
                `;

                columns.appendChild(col);
            });
        }

        function renderRecentActivity(items) {
            recentActivityList.innerHTML = "";

            if (!Array.isArray(items) || items.length === 0) {
                recentActivityList.innerHTML = `<div class="empty-state">No recent login activity found.</div>`;
                return;
            }

            items.forEach(item => {
                const status = item.status === "failed" ? "failed" : "success";
                const row = document.createElement("div");
                row.className = "recent-activity-row";

                row.innerHTML = `
                    <div class="recent-activity-status ${status === "failed" ? "status-failed" : "status-success"}">
                        ${status === "failed" ? "✕" : "✓"}
                    </div>
                    <div class="recent-activity-main">
                        <div class="recent-activity-label ${status === "failed" ? "failed-text" : ""}">
                            ${escapeHtml(item.label || "")}
                        </div>
                        <div class="recent-activity-date">${escapeHtml(item.date || "")}</div>
                    </div>
                    <div class="recent-activity-meta">${escapeHtml(item.location || "Unknown Location")}</div>
                    <div class="recent-activity-meta">${escapeHtml(item.device || "Unknown Device")}</div>
                    <div class="recent-activity-ip">${escapeHtml(item.ip || "Unknown IP")}</div>
                `;

                recentActivityList.appendChild(row);
            });
        }

        function updateLiveActivity(data) {
            renderLiveActivityChart(
                data.liveSuccessSeries || [],
                data.liveFailedSeries || [],
                data.liveLabels || [],
                data.liveDates || []
            );

            todaySuccessCount.textContent = String(data.todaySuccess ?? 0);
            todayFailedCount.textContent = String(data.todayFailed ?? 0);
            weekSuccessCount.textContent = String(data.weekSuccess ?? 0);
            weekFailedCount.textContent = String(data.weekFailed ?? 0);
            successRateValue.textContent = `${data.successRate ?? 0}%`;
            totalAttemptsValue.textContent = String(data.totalAttempts ?? 0);

            renderRecentActivity(data.recentActivity || []);
        }

        function updateDashboard(data) {
            renderNews(data.newsItems || []);
            renderVulns(data.recentVulns || []);
            updateLiveActivity(data);

            const online = data.feedOnline || data.advisoryOnline;
            feedStatusText.textContent = online ? "Live Feed Online" : "Feed Offline";
            liveStatusBar.className = online ? "live-status-bar" : "live-status-bar offline";

            if (data.feedError && data.feedError.trim() !== "") {
                feedWarning.textContent = data.feedError;
                feedWarning.classList.remove("hidden-warning");
            } else {
                feedWarning.textContent = "";
                feedWarning.classList.add("hidden-warning");
            }
        }

        let currentTool = "home";

        const tipLibrary = {
            home: [
                "Enable MFA on all primary accounts.",
                "Prioritize known exploited vulnerabilities first.",
                "Review CISA alerts regularly for active threat guidance.",
                "Use long, unique passwords for important services.",
                "Keep browsers and operating systems fully updated.",
                "Back up important files regularly.",
                "Limit admin privileges wherever possible.",
                "Watch for suspicious links and attachments."
            ],
            password: [
                "Use long passwords or passphrases for better strength.",
                "Avoid reusing passwords across different websites.",
                "Longer passwords are usually better than short complex ones.",
                "Do not include names, birthdays, or common words alone.",
                "Use a password manager to store strong unique passwords.",
                "Mix letters, numbers, and symbols when needed.",
                "Change exposed passwords immediately after a breach.",
                "Do not save important passwords in plain text files."
            ],
            phishing: [
                "Check sender addresses carefully before trusting messages.",
                "Hover over links before clicking them.",
                "Treat urgent account warnings with caution.",
                "Unexpected attachments should always be reviewed carefully.",
                "Watch for lookalike domains and subtle misspellings.",
                "Do not enter credentials on pages reached from suspicious emails.",
                "Report suspicious emails instead of interacting with them.",
                "Verify requests for money, login, or MFA codes separately."
            ],
            breach: [
                "Change exposed passwords immediately.",
                "Do not reuse a password found in a breach.",
                "Enable MFA after resetting important accounts.",
                "Review account login history for suspicious access.",
                "Check recovery email and phone settings.",
                "Sign out of old sessions after a suspected compromise.",
                "Update security questions if they are weak or reused.",
                "Review other accounts using the same or similar password."
            ]
        };

        function shuffleArray(array) {
            const copy = [...array];
            for (let i = copy.length - 1; i > 0; i--) {
                const j = Math.floor(Math.random() * (i + 1));
                [copy[i], copy[j]] = [copy[j], copy[i]];
            }
            return copy;
        }

        function detectCurrentTool() {
            const activeNav = document.querySelector(".dash-nav-item.active");
            if (activeNav && activeNav.dataset.tool) {
                currentTool = activeNav.dataset.tool;
            } else {
                currentTool = "home";
            }
        }

        function getCurrentTips() {
            return tipLibrary[currentTool] || tipLibrary.home;
        }

        function renderTips(tips) {
            tipsList.innerHTML = "";

            if (!tips.length) {
                tipsEmptyState.classList.remove("hidden-warning");
                return;
            }

            tipsEmptyState.classList.add("hidden-warning");

            tips.forEach(tip => {
                const div = document.createElement("div");
                div.className = "tip-box";
                div.textContent = tip;
                tipsList.appendChild(div);
            });
        }

        function loadDefaultTips() {
            const tips = shuffleArray(getCurrentTips()).slice(0, 3);
            renderTips(tips);
        }

        function searchTips() {
            const query = tipsSearch.value.trim().toLowerCase();
            const tips = getCurrentTips();

            if (!query) {
                loadDefaultTips();
                return;
            }

            const filtered = tips.filter(tip => tip.toLowerCase().includes(query));
            renderTips(filtered);
        }

        shuffleTipsBtn.addEventListener("click", function () {
            tipsSearch.value = "";
            loadDefaultTips();
        });

        tipsSearch.addEventListener("input", function () {
            searchTips();
        });

        async function fetchDashboardData(showStatus = true) {
            try {
                if (showStatus) {
                    liveUpdateLabel.textContent = "Refreshing...";
                }

                const response = await fetch("vuln_stream.php?ts=" + Date.now(), {
                    cache: "no-store"
                });

                if (!response.ok) {
                    throw new Error("Request failed");
                }

                const data = await response.json();
                updateDashboard(data);
                liveUpdateLabel.textContent = "Updated: " + new Date().toLocaleTimeString();
            } catch (error) {
                liveUpdateLabel.textContent = "Refresh failed";
            }
        }

        manualRefreshBtn.addEventListener("click", function () {
            fetchDashboardData(true);
        });

        updateLiveActivity({
            liveSuccessSeries: <?= json_encode($liveActivity["successSeries"]) ?>,
            liveFailedSeries: <?= json_encode($liveActivity["failedSeries"]) ?>,
            liveLabels: <?= json_encode($liveActivity["labels"]) ?>,
            liveDates: <?= json_encode($liveActivity["dates"]) ?>,
            todaySuccess: <?= (int) $liveActivity["todaySuccess"] ?>,
            todayFailed: <?= (int) $liveActivity["todayFailed"] ?>,
            weekSuccess: <?= (int) $liveActivity["weekSuccess"] ?>,
            weekFailed: <?= (int) $liveActivity["weekFailed"] ?>,
            successRate: <?= (int) $liveActivity["successRate"] ?>,
            totalAttempts: <?= (int) $liveActivity["totalAttempts"] ?>,
            recentActivity: <?= json_encode($liveActivity["recentActivity"]) ?>
        });

        detectCurrentTool();
        loadDefaultTips();
        fetchDashboardData(false);

        setInterval(function () {
            fetchDashboardData(false);
        }, 60000);
    </script>
</body>
</html>
