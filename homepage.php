<?php
session_start();

header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Cache-Control: post-check=0, pre-check=0", false);
header("Pragma: no-cache");
header("Expires: 0");

date_default_timezone_set("America/Chicago");

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
$sansFeedUrl = "https://isc.sans.edu/rssfeed_full.xml";
$unit42Url = "https://unit42.paloaltonetworks.com/";

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
    $action = strtolower((string) ($requiredAction));

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

function normalizeNewsDate(?string $value): int
{
    $value = trim((string) ($value ?? ""));
    if ($value === "") {
        return 0;
    }

    $ts = strtotime($value);
    return $ts !== false ? $ts : 0;
}

function addNewsItem(array &$newsItems, array $item): void
{
    $title = trim((string) ($item["title"] ?? ""));
    $link = trim((string) ($item["link"] ?? ""));

    if ($title === "" || $link === "") {
        return;
    }

    foreach ($newsItems as $existing) {
        if (
            trim((string) ($existing["title"] ?? "")) === $title ||
            trim((string) ($existing["link"] ?? "")) === $link
        ) {
            return;
        }
    }

    $newsItems[] = $item;
}

function fetchSansNews(string $feedUrl): array
{
    $items = [];
    $raw = fetchUrl($feedUrl);

    if ($raw === false) {
        return $items;
    }

    libxml_use_internal_errors(true);
    $xml = simplexml_load_string($raw);

    if ($xml === false || empty($xml->channel->item)) {
        return $items;
    }

    foreach ($xml->channel->item as $entry) {
        $title = trim((string) ($entry->title ?? ""));
        $link = trim((string) ($entry->link ?? ""));
        $dateText = trim((string) ($entry->pubDate ?? ""));
        $description = trim(strip_tags((string) ($entry->description ?? "")));

        if ($title === "" || $link === "") {
            continue;
        }

        $items[] = [
            "title" => $title,
            "summary" => $description !== "" ? $description : "Latest update from SANS Internet Storm Center.",
            "meta" => "Source: SANS ISC",
            "date" => $dateText !== "" ? date("M j, Y", strtotime($dateText)) : "",
            "link" => $link,
            "timestamp" => normalizeNewsDate($dateText)
        ];

        if (count($items) >= 4) {
            break;
        }
    }

    return $items;
}

function normalizeWhitespace(string $text): string
{
    return trim(preg_replace('/\s+/', ' ', $text));
}

function formatDateText(?string $raw): string
{
    $raw = trim((string) $raw);
    if ($raw === "") {
        return "";
    }

    $ts = strtotime($raw);
    if ($ts === false) {
        return "";
    }

    return date("M j, Y", $ts);
}

function fetchUnit42News(string $url): array
{
    $items = [];
    $raw = fetchUrl($url);

    if ($raw === false) {
        return $items;
    }

    preg_match_all('/([A-Za-z]+\s+\d{1,2},\s+\d{4}).{0,250}?<a[^>]*href="([^"]+)"[^>]*>(.*?)<\/a>/is', $raw, $matches, PREG_SET_ORDER);

    $seenLinks = [];

    foreach ($matches as $match) {
        $dateText = trim((string) ($match[1] ?? ""));
        $href = html_entity_decode((string) ($match[2] ?? ""), ENT_QUOTES | ENT_HTML5);
        $title = normalizeWhitespace(strip_tags((string) ($match[3] ?? "")));

        if ($title === "" || $href === "" || $dateText === "") {
            continue;
        }

        if (!str_starts_with($href, "http")) {
            $href = "https://unit42.paloaltonetworks.com" . $href;
        }

        if (isset($seenLinks[$href])) {
            continue;
        }
        $seenLinks[$href] = true;

        $items[] = [
            "title" => $title,
            "summary" => "Latest threat research and intelligence from Palo Alto Networks Unit 42.",
            "meta" => "Source: Unit 42",
            "date" => formatDateText($dateText),
            "link" => $href,
            "timestamp" => normalizeNewsDate($dateText)
        ];

        if (count($items) >= 4) {
            break;
        }
    }

    return $items;
}

function formatEventTypeLabel(string $eventType): string
{
    $eventType = strtolower(trim($eventType));

    if ($eventType === "successful_login") {
        return "Successful Login";
    }

    if ($eventType === "failed_login") {
        return "Failed Login";
    }

    if ($eventType === "") {
        return "No Recent Activity";
    }

    return ucwords(str_replace("_", " ", $eventType));
}

function buildAttackMetrics(PDO $pdo, int $userId): array
{
    $series = [];
    $labels = [];
    $dates = [];
    $weekCount = 0;

    $tz = new DateTimeZone("America/Chicago");
    $today = new DateTimeImmutable("now", $tz);
    $today = $today->setTime(0, 0, 0);

    $countStmt = $pdo->prepare("
        SELECT COUNT(*)
        FROM public.login_activity
        WHERE user_id = ?
          AND created_at BETWEEN ? AND ?
          AND LOWER(TRIM(COALESCE(event_type, ''))) = ?
    ");

    for ($i = 6; $i >= 0; $i--) {
        $day = $today->modify("-{$i} days");

        $dayStart = $day->format("Y-m-d 00:00:00");
        $dayEnd = $day->format("Y-m-d 23:59:59");

        $countStmt->execute([
            $userId,
            $dayStart,
            $dayEnd,
            "successful_login"
        ]);

        $count = (int) $countStmt->fetchColumn();

        $series[] = $count;
        $labels[] = $day->format("D");
        $dates[] = $day->format("M j");
        $weekCount += $count;
    }

    $todayCount = end($series);
    if ($todayCount === false) {
        $todayCount = 0;
    }

    $latestType = "No Recent Activity";
    $latestDetails = "No recent login details available.";

    $latestStmt = $pdo->prepare("
        SELECT event_type, created_at, ip_address, location, city, region, country
        FROM public.login_activity
        WHERE user_id = ?
          AND LOWER(TRIM(COALESCE(event_type, ''))) = ?
        ORDER BY created_at DESC
        LIMIT 1
    ");

    $latestStmt->execute([
        $userId,
        "successful_login"
    ]);

    $latestRow = $latestStmt->fetch(PDO::FETCH_ASSOC);

    if ($latestRow) {
        $latestType = formatEventTypeLabel((string) ($latestRow["event_type"] ?? ""));

        $detailParts = [];

        $createdAtRaw = trim((string) ($latestRow["created_at"] ?? ""));
        if ($createdAtRaw !== "") {
            $createdTs = strtotime($createdAtRaw);
            if ($createdTs !== false) {
                $detailParts[] = date("M j, Y g:i A", $createdTs);
            }
        }

        $ipAddress = trim((string) ($latestRow["ip_address"] ?? ""));
        if ($ipAddress !== "") {
            $detailParts[] = "IP: " . $ipAddress;
        }

        $location = trim((string) ($latestRow["location"] ?? ""));
        $city = trim((string) ($latestRow["city"] ?? ""));
        $region = trim((string) ($latestRow["region"] ?? ""));
        $country = trim((string) ($latestRow["country"] ?? ""));

        $cityRegionCountry = array_values(array_filter([$city, $region, $country], function ($value) {
            return trim((string) $value) !== "";
        }));

        if ($location !== "") {
            $detailParts[] = "Location: " . $location;
        } elseif (!empty($cityRegionCountry)) {
            $detailParts[] = "Location: " . implode(", ", $cityRegionCountry);
        } else {
            $detailParts[] = "Location data unavailable";
        }
    }

    return [
        "series" => $series,
        "labels" => $labels,
        "dates" => $dates,
        "currentCount" => $todayCount,
        "weekCount" => $weekCount,
        "latestType" => $latestType,
        "latestDetails" => $latestDetails
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

            addNewsItem($newsItems, [
                "title" => $title,
                "summary" => "Live update from CISA Cybersecurity Alerts & Advisories.",
                "meta" => "Source: CISA",
                "date" => $dateText,
                "link" => $href,
                "timestamp" => normalizeNewsDate($dateText)
            ]);
        }

        if (count($newsItems) >= 4) {
            break;
        }
    }
} else {
    $feedError .= "Unable to load CISA advisories page. ";
}

$sansItems = fetchSansNews($sansFeedUrl);
if (empty($sansItems)) {
    $feedError .= "Unable to load SANS ISC feed. ";
} else {
    foreach ($sansItems as $item) {
        addNewsItem($newsItems, $item);
    }
}

$unit42Items = fetchUnit42News($unit42Url);
if (empty($unit42Items)) {
    $feedError .= "Unable to load Unit 42 updates. ";
} else {
    foreach ($unit42Items as $item) {
        addNewsItem($newsItems, $item);
    }
}

usort($newsItems, function ($a, $b) {
    return ((int) ($b["timestamp"] ?? 0)) <=> ((int) ($a["timestamp"] ?? 0));
});

$newsItems = array_slice($newsItems, 0, 4);

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
            "link" => "#",
            "timestamp" => time()
        ]
    ];
}

$attackMetrics = buildAttackMetrics($pdo, $userId);

$alertCount = count($recentVulns);
$threatScore = getThreatScore($alertCount);
$passwordHealth = "Strong";
$feedStatusText = ($feedOnline || $advisoryOnline || !empty($sansItems) || !empty($unit42Items)) ? "Live Feed Online" : "Feed Offline";
$liveStatusClass = ($feedOnline || $advisoryOnline || !empty($sansItems) || !empty($unit42Items)) ? "live-status-bar" : "live-status-bar offline";

$latestDetailLines = array_filter(array_map('trim', explode(' • ', (string) ($attackMetrics["latestDetails"] ?? ""))));
?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Homepage | Optimsecurity</title>
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="homepage.css">
    <link rel="icon" href="/favicon.ico" type="image/x-icon">

    <link rel="icon" type="image/png" sizes="32x32" href="/favicon-32x32.png">
    <link rel="icon" type="image/png" sizes="16x16" href="/favicon-16x16.png">

    <link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png">
    <link rel="manifest" href="/site.webmanifest">
    <style>
        .attack-latest-wrap {
            margin-top: 12px;
            display: flex;
            flex-direction: column;
            align-items: flex-start;
            gap: 12px;
        }

        .attack-latest-title {
            font-size: 18px;
            font-weight: 700;
            color: #ffffff;
            line-height: 1.2;
        }

        .attack-latest-details {
            display: flex;
            flex-direction: column;
            gap: 6px;
            width: 100%;
        }

        .attack-latest-line {
            font-size: 16px;
            font-weight: 600;
            color: #ffffff;
            line-height: 1.35;
            word-break: break-word;
            overflow-wrap: anywhere;
        }
    </style>
</head>

<body class="dashboard-body">
    <div class="dash-shell">
        <aside class="dash-sidebar">
            <div class="dash-sidebar-title">
                <img src="optimsecuritylogo.png" alt="Optimsecurity" class="sidebar-logo">
            </div>

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
                            <a class="news-item live-news news-link-card" href="<?= htmlspecialchars($item["link"]) ?>"
                                target="_blank" rel="noopener noreferrer">
                                <div class="news-head"><?= safeText($item["title"]) ?></div>
                                <div class="news-sub"><?= safeText($item["summary"]) ?></div>
                                <div class="news-meta">
                                    <?= safeText($item["meta"]) ?>
                                    <?php if (!empty($item["date"])): ?>
                                        • <?= safeText($item["date"]) ?>
                                    <?php endif; ?>
                                </div>
                            </a>
                        <?php endforeach; ?>
                    </div>
                </div>

                <div class="dash-card">
                    <div class="card-header">
                        <h2>Login Activity</h2>
                    </div>

                    <div class="chart-box live-chart-box weekly-chart-box">
                        <div class="weekly-chart-topline">
                            <span>This Week</span>
                            <span>Your Security Events</span>
                        </div>

                        <div class="attack-week-chart" id="attackWeekChart"></div>
                    </div>

                    <div class="attack-live-stats">
                        <div class="attack-mini-card">
                            <span class="attack-mini-label">Today</span>
                            <span class="attack-mini-value"
                                id="attackCurrentCount"><?= (int) $attackMetrics["currentCount"] ?></span>
                        </div>

                        <div class="attack-mini-card">
                            <span class="attack-mini-label">This Week</span>
                            <span class="attack-mini-value"
                                id="attackWeekCount"><?= (int) $attackMetrics["weekCount"] ?></span>
                        </div>
                    </div>

                    <div class="attack-latest-card">
                        <span class="attack-mini-label">
                            Latest: <?= htmlspecialchars($attackMetrics["latestType"]) ?>
                        </span>

                        <div class="attack-latest-details" id="attackTrendDetails">
                            <?php if (!empty($latestDetailLines)): ?>
                                <?php foreach ($latestDetailLines as $line): ?>
                                    <div class="attack-latest-line"><?= htmlspecialchars($line) ?></div>
                                <?php endforeach; ?>
                            <?php else: ?>
                                <div class="attack-latest-line">No recent login details available.</div>
                            <?php endif; ?>
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
                            <input type="text" id="tipsSearch" class="tips-search-input"
                                placeholder="Search tips like MFA, phishing, passwords...">
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

            <section class="dash-features">
                <div class="features-title">Quick Access</div>

                <div class="tertiary-grid">
                    <div class="tertiary-box">
                        <h3>Password Tools</h3>
                        <p>Quick access to password analysis and generator features.</p>
                        <div class="tertiary-action">
                            <a class="tertiary-link" href="password_checker.php">Open Tools</a>
                        </div>
                    </div>

                    <div class="tertiary-box">
                        <h3>Password Vault</h3>
                        <p>Store and manage saved usernames, passwords, and notes from your dashboard.</p>
                        <div class="tertiary-action">
                            <a class="tertiary-link" href="vault.php">Open Vault</a>
                        </div>
                    </div>

                    <div class="tertiary-box">
                        <h3>Phishing Checks</h3>
                        <p>Analyze suspicious content, messages, and URLs.</p>
                        <div class="tertiary-action">
                            <a class="tertiary-link" href="phishing_toolkit.php">Run Check</a>
                        </div>
                    </div>

                    <div class="tertiary-box">
                        <h3>Activity</h3>
                        <p>Track recent dashboard and account events.</p>
                        <div class="tertiary-action">
                            <a class="tertiary-link" href="homepage.php">View Activity</a>
                        </div>
                    </div>

                    <div class="tertiary-box">
                        <h3>Threat Intel</h3>
                        <p>Monitor live vulnerability and advisory updates from official sources.</p>
                        <div class="tertiary-action">
                            <a class="tertiary-link" href="homepage.php">View Feed</a>
                        </div>
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
        const attackWeekChart = document.getElementById("attackWeekChart");
        const attackTrendMeta = document.getElementById("attackTrendMeta");
        const attackTrendDetails = document.getElementById("attackTrendDetails");
        const attackCurrentCount = document.getElementById("attackCurrentCount");
        const attackWeekCount = document.getElementById("attackWeekCount");

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

                const metaText = item.date
                    ? `${escapeHtml(item.meta || "")} • ${escapeHtml(item.date)}`
                    : `${escapeHtml(item.meta || "")}`;

                a.innerHTML = `
                    <div class="news-head">${escapeHtml(item.title || "Untitled Update")}</div>
                    <div class="news-sub">${escapeHtml(item.summary || "")}</div>
                    <div class="news-meta">${metaText}</div>
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

        function renderAttackWeek(series, labels, dates) {
            const safeSeries = Array.isArray(series) && series.length > 0
                ? series.map(value => Number(value) || 0)
                : [0, 0, 0, 0, 0, 0, 0];

            const safeLabels = Array.isArray(labels) && labels.length === safeSeries.length
                ? labels
                : ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];

            const safeDates = Array.isArray(dates) && dates.length === safeSeries.length
                ? dates
                : ["", "", "", "", "", "", ""];

            const latestIndex = safeSeries.length - 1;
            const hasAnyData = safeSeries.some(value => value > 0);

            const chartMax = Math.max(4, ...safeSeries);

            attackWeekChart.innerHTML = "";

            safeSeries.forEach((value, index) => {
                const col = document.createElement("div");
                col.className = "attack-week-col";

                if (index === latestIndex) {
                    col.classList.add("active-day");
                }

                const plot = document.createElement("div");
                plot.className = "attack-week-plot";

                const bar = document.createElement("div");
                bar.className = "attack-week-bar";

                let percent = 0;

                if (hasAnyData) {
                    percent = value > 0 ? (value / chartMax) * 100 : 0;
                } else {
                    percent = 2.5;
                    bar.classList.add("zero-bar");
                }

                bar.style.height = `${percent}%`;
                bar.title = `${safeLabels[index]} ${safeDates[index]}: ${value} login${value === 1 ? "" : "s"}`;

                const day = document.createElement("div");
                day.className = "attack-week-day";
                day.textContent = safeLabels[index];

                const date = document.createElement("div");
                date.className = "attack-week-date";
                date.textContent = safeDates[index];

                plot.appendChild(bar);
                col.appendChild(plot);
                col.appendChild(day);
                col.appendChild(date);

                attackWeekChart.appendChild(col);
            });

            if (!hasAnyData) {
                const empty = document.createElement("div");
                empty.className = "attack-week-empty";
                empty.textContent = "No login activity this week";
                attackWeekChart.appendChild(empty);
            }
        }

        function renderAttackLatest(latestType, latestDetails) {
            attackTrendMeta.textContent = `Latest: ${latestType || "No Recent Activity"}`;

            const detailText = latestDetails || "No recent login details available.";
            const detailLines = detailText.split("•").map(part => part.trim()).filter(Boolean);

            attackTrendDetails.innerHTML = "";

            if (!detailLines.length) {
                const div = document.createElement("div");
                div.className = "attack-latest-line";
                div.textContent = "No recent login details available.";
                attackTrendDetails.appendChild(div);
                return;
            }

            detailLines.forEach(line => {
                const div = document.createElement("div");
                div.className = "attack-latest-line";
                div.textContent = line;
                attackTrendDetails.appendChild(div);
            });
        }

        function updateAttackActivity(series, labels, dates, latestType, latestDetails, currentCount, weekCount) {
            renderAttackWeek(series, labels, dates);
            attackCurrentCount.textContent = String(currentCount ?? 0);
            attackWeekCount.textContent = String(weekCount ?? 0);
            renderAttackLatest(latestType, latestDetails);
        }

        function updateDashboard(data) {
            renderNews(data.newsItems || []);
            renderVulns(data.recentVulns || []);

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

            updateAttackActivity(
                data.attackSeries || [],
                data.attackLabels || [],
                data.attackDates || [],
                data.attackLatestType || "No Recent Activity",
                data.attackLatestDetails || "",
                data.attackCurrentCount || 0,
                data.attackWeekCount || 0
            );
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

        updateAttackActivity(
            <?= json_encode($attackMetrics["series"]) ?>,
            <?= json_encode($attackMetrics["labels"]) ?>,
            <?= json_encode($attackMetrics["dates"]) ?>,
            <?= json_encode($attackMetrics["latestType"]) ?>,
            <?= json_encode($attackMetrics["latestDetails"]) ?>,
            <?= (int) $attackMetrics["currentCount"] ?>,
            <?= (int) $attackMetrics["weekCount"] ?>
        );

        detectCurrentTool();
        loadDefaultTips();
        fetchDashboardData(false);

        setInterval(function () {
            fetchDashboardData(false);
        }, 60000);
    </script>
</body>

</html>
