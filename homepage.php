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

require_once __DIR__ . "/db.php";

$name = $_SESSION["user_name"] ?? "User";

$kevUrl = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
$advisoriesUrl = "https://www.cisa.gov/news-events/cybersecurity-advisories";

$recentVulns = [];
$newsItems = [];
$feedError = "";
$feedOnline = false;
$advisoryOnline = false;

$selectedDay = trim((string)($_GET["activity_day"] ?? ""));
$tipQuery = trim((string)($_GET["tips_q"] ?? ""));
$shuffleTips = isset($_GET["shuffle_tips"]);

function safeText($value, $default = "N/A")
{
    $value = trim((string)($value ?? ""));
    return $value !== "" ? htmlspecialchars($value) : $default;
}

function safeRawText($value, $default = "N/A")
{
    $value = trim((string)($value ?? ""));
    return $value !== "" ? $value : $default;
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
    $action = strtolower((string)$requiredAction);

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

function getLoginActivityColumns(PDO $pdo): array
{
    static $cached = null;

    if ($cached !== null) {
        return $cached;
    }

    $stmt = $pdo->prepare("
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'login_activity'
    ");
    $stmt->execute();

    $cached = $stmt->fetchAll(PDO::FETCH_COLUMN) ?: [];
    return $cached;
}

function firstExistingColumn(array $columns, array $candidates): ?string
{
    foreach ($candidates as $candidate) {
        if (in_array($candidate, $columns, true)) {
            return $candidate;
        }
    }
    return null;
}

function quoteIdent(string $identifier): string
{
    return '"' . str_replace('"', '""', $identifier) . '"';
}

function getLoginActivityColumnMap(PDO $pdo): array
{
    $columns = getLoginActivityColumns($pdo);

    return [
        "timestamp"  => firstExistingColumn($columns, ["created_at", "login_at", "event_time", "occurred_at", "timestamp"]),
        "ip"         => firstExistingColumn($columns, ["ip_address", "ip_addr", "ip"]),
        "location"   => firstExistingColumn($columns, ["location", "geo_location"]),
        "city"       => firstExistingColumn($columns, ["city"]),
        "region"     => firstExistingColumn($columns, ["region", "state", "province"]),
        "country"    => firstExistingColumn($columns, ["country"]),
        "event_type" => firstExistingColumn($columns, ["event_type", "type", "activity_type"]),
        "user_agent" => firstExistingColumn($columns, ["user_agent", "device_info", "device"]),
        "user_id"    => firstExistingColumn($columns, ["user_id", "account_id"]),
    ];
}

function buildLocationString(array $row, array $map): string
{
    $parts = [];

    if ($map["location"] !== null && !empty($row[$map["location"]])) {
        return trim((string)$row[$map["location"]]);
    }

    foreach (["city", "region", "country"] as $partKey) {
        $col = $map[$partKey] ?? null;
        if ($col !== null) {
            $value = trim((string)($row[$col] ?? ""));
            if ($value !== "") {
                $parts[] = $value;
            }
        }
    }

    return !empty($parts) ? implode(", ", $parts) : "Unknown";
}

function buildAttackMetrics(PDO $pdo): array
{
    $map = getLoginActivityColumnMap($pdo);
    $timeCol = $map["timestamp"];

    $series = [];
    $labels = [];
    $dates = [];
    $isoDates = [];
    $weekCount = 0;

    if ($timeCol === null) {
        for ($i = 6; $i >= 0; $i--) {
            $dayTs = strtotime("-$i days");
            $series[] = 0;
            $labels[] = date("D", $dayTs);
            $dates[] = date("M j", $dayTs);
            $isoDates[] = date("Y-m-d", $dayTs);
        }

        return [
            "series" => $series,
            "labels" => $labels,
            "dates" => $dates,
            "isoDates" => $isoDates,
            "currentCount" => 0,
            "weekCount" => 0,
            "latestType" => "No Activity Column Found"
        ];
    }

    $sql = "
        SELECT COUNT(*)
        FROM public.login_activity
        WHERE " . quoteIdent($timeCol) . " >= ?
          AND " . quoteIdent($timeCol) . " < ?
    ";

    if ($map["user_id"] !== null && isset($_SESSION["user_id"])) {
        $sql .= " AND " . quoteIdent($map["user_id"]) . " = ?";
    }

    $stmt = $pdo->prepare($sql);

    for ($i = 6; $i >= 0; $i--) {
        $dayTs = strtotime("-$i days");
        $dayStart = date("Y-m-d 00:00:00", $dayTs);
        $dayEnd = date("Y-m-d 00:00:00", strtotime("+1 day", strtotime($dayStart)));

        $params = [$dayStart, $dayEnd];
        if ($map["user_id"] !== null && isset($_SESSION["user_id"])) {
            $params[] = $_SESSION["user_id"];
        }

        $stmt->execute($params);
        $count = (int)$stmt->fetchColumn();

        $series[] = $count;
        $labels[] = date("D", $dayTs);
        $dates[] = date("M j", $dayTs);
        $isoDates[] = date("Y-m-d", $dayTs);
        $weekCount += $count;
    }

    $todayCount = end($series);
    if ($todayCount === false) {
        $todayCount = 0;
    }

    return [
        "series" => $series,
        "labels" => $labels,
        "dates" => $dates,
        "isoDates" => $isoDates,
        "currentCount" => (int)$todayCount,
        "weekCount" => $weekCount,
        "latestType" => "Successful Login"
    ];
}

function getActivityDayDetails(PDO $pdo, string $day): ?array
{
    if (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $day)) {
        return null;
    }

    $map = getLoginActivityColumnMap($pdo);
    $timeCol = $map["timestamp"];

    if ($timeCol === null) {
        return [
            "label" => date("D M j", strtotime($day)),
            "total" => 0,
            "rows" => []
        ];
    }

    $selectParts = [];
    $aliases = [
        "timestamp" => "created_at",
        "ip" => "ip",
        "event_type" => "event_type",
        "user_agent" => "user_agent"
    ];

    foreach ($aliases as $mapKey => $alias) {
        $col = $map[$mapKey] ?? null;
        if ($col !== null) {
            $selectParts[] = quoteIdent($col) . " AS " . quoteIdent($alias);
        }
    }

    foreach (["location", "city", "region", "country"] as $mapKey) {
        $col = $map[$mapKey] ?? null;
        if ($col !== null) {
            $selectParts[] = quoteIdent($col) . " AS " . quoteIdent($mapKey);
        }
    }

    if (empty($selectParts)) {
        $selectParts[] = "NULL AS created_at";
    }

    $sql = "
        SELECT " . implode(", ", $selectParts) . "
        FROM public.login_activity
        WHERE " . quoteIdent($timeCol) . " >= ?
          AND " . quoteIdent($timeCol) . " < ?
    ";

    $params = [
        $day . " 00:00:00",
        date("Y-m-d 00:00:00", strtotime($day . " +1 day"))
    ];

    if ($map["user_id"] !== null && isset($_SESSION["user_id"])) {
        $sql .= " AND " . quoteIdent($map["user_id"]) . " = ?";
        $params[] = $_SESSION["user_id"];
    }

    $sql .= " ORDER BY " . quoteIdent($timeCol) . " DESC LIMIT 10";

    $stmt = $pdo->prepare($sql);
    $stmt->execute($params);
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC) ?: [];

    foreach ($rows as &$row) {
        $row["location_display"] = buildLocationString($row, [
            "location" => "location",
            "city" => "city",
            "region" => "region",
            "country" => "country"
        ]);
    }
    unset($row);

    return [
        "label" => date("D M j", strtotime($day)),
        "total" => count($rows),
        "rows" => $rows
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

$attackMetrics = buildAttackMetrics($pdo);
$selectedDetails = $selectedDay !== "" ? getActivityDayDetails($pdo, $selectedDay) : null;

$alertCount = count($recentVulns);
$threatScore = getThreatScore($alertCount);
$passwordHealth = "Strong";
$feedStatusText = ($feedOnline || $advisoryOnline) ? "Live Feed Online" : "Feed Offline";
$liveStatusClass = ($feedOnline || $advisoryOnline) ? "live-status-bar" : "live-status-bar offline";
$serverUpdatedLabel = "Updated: " . date("g:i A");

$tipLibrary = [
    "home" => [
        "Enable MFA on all primary accounts.",
        "Prioritize known exploited vulnerabilities first.",
        "Review CISA alerts regularly for active threat guidance.",
        "Use long, unique passwords for important services.",
        "Keep browsers and operating systems fully updated.",
        "Back up important files regularly.",
        "Limit admin privileges wherever possible.",
        "Watch for suspicious links and attachments."
    ]
];

$currentTips = $tipLibrary["home"];

if ($shuffleTips) {
    shuffle($currentTips);
}

if ($tipQuery !== "") {
    $currentTips = array_values(array_filter($currentTips, function ($tip) use ($tipQuery) {
        return stripos($tip, $tipQuery) !== false;
    }));
} else {
    $currentTips = array_slice($currentTips, 0, 3);
}

$maxValue = max($attackMetrics["series"]);
$chartTop = max($maxValue + 1, 5);
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
                        <div class="<?= htmlspecialchars($liveStatusClass) ?>">
                            <span class="live-status-left">
                                <span class="status-dot"></span>
                                <span><?= htmlspecialchars($feedStatusText) ?></span>
                            </span>

                            <span class="live-status-divider"></span>

                            <span class="live-status-right"><?= htmlspecialchars($serverUpdatedLabel) ?></span>
                        </div>

                        <a class="refresh-btn" href="homepage.php">Refresh Feed</a>
                    </div>

                    <div class="feed-warning<?= trim($feedError) === '' ? ' hidden-warning' : '' ?>">
                        <?= htmlspecialchars(trim($feedError)) ?>
                    </div>

                    <div class="news-list">
                        <?php foreach ($newsItems as $item): ?>
                            <a class="news-item live-news news-link-card"
                               href="<?= htmlspecialchars($item["link"]) ?>"
                               target="_blank"
                               rel="noopener noreferrer">
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
                            <span>Click a bar for details</span>
                        </div>

                        <div class="attack-week-chart nojs-chart" style="--chart-top: <?= (int)$chartTop ?>;">
                            <?php foreach ($attackMetrics["series"] as $index => $value): ?>
                                <?php
                                $label = $attackMetrics["labels"][$index] ?? "";
                                $dateText = $attackMetrics["dates"][$index] ?? "";
                                $isoDate = $attackMetrics["isoDates"][$index] ?? "";
                                $percent = $value > 0 ? ($value / $chartTop) * 100 : 0;
                                $isActive = ($selectedDay !== "" && $selectedDay === $isoDate) || ($selectedDay === "" && $index === count($attackMetrics["series"]) - 1);
                                ?>
                                <a
                                    class="attack-week-col<?= $isActive ? ' active-day' : '' ?>"
                                    href="homepage.php?activity_day=<?= urlencode($isoDate) ?>#activity-details"
                                    aria-label="<?= htmlspecialchars($label . ' ' . $dateText . ': ' . $value . ' events') ?>"
                                >
                                    <div class="attack-week-plot">
                                        <div class="attack-week-bar<?= $value === 0 ? ' zero-bar' : '' ?>" style="height: <?= htmlspecialchars((string)$percent) ?>%;"></div>
                                    </div>
                                    <div class="attack-week-value"><?= (int)$value ?></div>
                                    <div class="attack-week-day"><?= htmlspecialchars($label) ?></div>
                                    <div class="attack-week-date"><?= htmlspecialchars($dateText) ?></div>
                                </a>
                            <?php endforeach; ?>
                        </div>
                    </div>

                    <div class="attack-live-stats">
                        <div class="attack-mini-card">
                            <span class="attack-mini-label">Today</span>
                            <span class="attack-mini-value"><?= (int)$attackMetrics["currentCount"] ?></span>
                        </div>

                        <div class="attack-mini-card">
                            <span class="attack-mini-label">This Week</span>
                            <span class="attack-mini-value"><?= (int)$attackMetrics["weekCount"] ?></span>
                        </div>
                    </div>

                    <div class="activity-footer-strip" id="activity-details">
                        <div class="activity-footer-left">
                            <div class="activity-footer-icon">✓</div>
                            <div class="activity-footer-copy">
                                <div class="activity-footer-title">Latest: Successful Login</div>
                                <div class="activity-footer-meta">
                                    <?php if ($selectedDetails && !empty($selectedDetails["rows"])): ?>
                                        <?= htmlspecialchars($selectedDetails["label"]) ?> • <?= (int)$selectedDetails["total"] ?> event(s) found
                                    <?php else: ?>
                                        Click a bar to load details.
                                    <?php endif; ?>
                                </div>
                            </div>
                        </div>

                        <a class="activity-footer-btn" href="#activity-day-panel">View Details</a>
                    </div>

                    <div class="dash-table-like activity-day-panel" id="activity-day-panel">
                        <?php if ($selectedDetails && !empty($selectedDetails["rows"])): ?>
                            <?php foreach ($selectedDetails["rows"] as $row): ?>
                                <div class="dash-row no-cve-row">
                                    <span class="row-dot"></span>

                                    <div class="row-main vuln-main">
                                        <div class="vuln-title">
                                            <?= htmlspecialchars(safeRawText($row["event_type"] ?? "Login Activity")) ?>
                                        </div>
                                        <div class="vuln-summary">
                                            IP: <?= htmlspecialchars(safeRawText($row["ip"] ?? "N/A")) ?>
                                            • Location: <?= htmlspecialchars(safeRawText($row["location_display"] ?? "Unknown")) ?>
                                        </div>
                                        <div class="vuln-meta">
                                            Time: <?= htmlspecialchars(safeRawText($row["created_at"] ?? "N/A")) ?>
                                        </div>
                                        <div class="vuln-meta">
                                            Device: <?= htmlspecialchars(safeRawText($row["user_agent"] ?? "N/A")) ?>
                                        </div>
                                    </div>

                                    <div class="row-side vuln-status-wrap">
                                        <span class="severity-pill sev-default">Activity</span>
                                    </div>
                                </div>
                            <?php endforeach; ?>
                        <?php elseif ($selectedDay !== ""): ?>
                            <div class="dash-row no-cve-row">
                                <span class="row-dot"></span>
                                <div class="row-main vuln-main">
                                    <div class="vuln-title">No details found</div>
                                    <div class="vuln-summary">There were no matching activity rows for this selected day.</div>
                                </div>
                            </div>
                        <?php endif; ?>
                    </div>
                </div>
            </section>

            <section class="dash-grid-bottom">
                <div class="dash-card">
                    <div class="card-header">
                        <h2>Recent Vulnerabilities</h2>
                    </div>

                    <div class="dash-table-like">
                        <?php foreach ($recentVulns as $vuln): ?>
                            <?php
                            $vendor = trim((string)($vuln["vendorProject"] ?? ""));
                            $product = trim((string)($vuln["product"] ?? ""));
                            $summary = trim((string)($vuln["shortDescription"] ?? "No description available."));
                            $actionLabel = getActionLabel($vuln["requiredAction"] ?? "");
                            $dateAdded = trim((string)($vuln["dateAdded"] ?? ""));

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
                        <form method="get" class="tips-search-wrapper" action="homepage.php">
                            <input
                                type="text"
                                name="tips_q"
                                class="tips-search-input"
                                placeholder="Search tips like MFA, phishing, passwords..."
                                value="<?= htmlspecialchars($tipQuery) ?>"
                            >
                        </form>

                        <a class="refresh-btn" href="homepage.php?shuffle_tips=1">New Tips</a>
                    </div>

                    <div class="tips-list">
                        <?php if (!empty($currentTips)): ?>
                            <?php foreach ($currentTips as $tip): ?>
                                <div class="tip-box"><?= htmlspecialchars($tip) ?></div>
                            <?php endforeach; ?>
                        <?php else: ?>
                            <div class="empty-state">No tips matched your search.</div>
                        <?php endif; ?>
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
</body>
</html>
