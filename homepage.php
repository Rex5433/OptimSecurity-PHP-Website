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

$name = $_SESSION["user_name"] ?? "User";

$kevUrl = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
$advisoriesUrl = "https://www.cisa.gov/news-events/cybersecurity-advisories";

$recentVulns = [];
$newsItems = [];
$feedError = "";
$feedOnline = false;
$advisoryOnline = false;

$tipsSearchQuery = trim((string) ($_GET["tips"] ?? ""));
$shuffleTips = isset($_GET["shuffle"]);
$lastLoadedText = date("M j, Y g:i A");

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

function buildAttackMetrics(PDO $pdo): array
{
    $series = [];
    $labels = [];
    $dates = [];
    $weekCount = 0;

    for ($i = 6; $i >= 0; $i--) {
        $dayTs = strtotime("-$i days");
        $dayStart = date("Y-m-d 00:00:00", $dayTs);
        $dayEnd = date("Y-m-d 23:59:59", $dayTs);

        $stmt = $pdo->prepare("
            SELECT COUNT(*)
            FROM public.login_activity
            WHERE created_at BETWEEN ? AND ?
        ");
        $stmt->execute([$dayStart, $dayEnd]);

        $count = (int) $stmt->fetchColumn();

        $series[] = $count;
        $labels[] = date("D", strtotime($dayStart));
        $dates[] = date("M j", strtotime($dayStart));
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
        "currentCount" => $todayCount,
        "weekCount" => $weekCount,
        "latestType" => "Activity Recorded"
    ];
}

function renderAttackWeekChart(array $series, array $labels, array $dates): string
{
    if (empty($series)) {
        $series = [0, 0, 0, 0, 0, 0, 0];
    }

    if (empty($labels) || count($labels) !== count($series)) {
        $labels = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
    }

    if (empty($dates) || count($dates) !== count($series)) {
        $dates = array_fill(0, count($series), "");
    }

    $maxValue = max($series);
    $hasAnyData = $maxValue > 0;
    $latestIndex = count($series) - 1;

    ob_start();
    ?>
    <div class="attack-week-chart">
        <?php foreach ($series as $index => $value): ?>
            <?php
            $value = (int) $value;
            $percent = 0;
            $barClass = "attack-week-bar";

            if ($hasAnyData) {
                $percent = $value > 0 ? max(($value / $maxValue) * 100, 8) : 0;
            } else {
                $percent = 2.5;
                $barClass .= " zero-bar";
            }

            $colClass = "attack-week-col";
            if ($index === $latestIndex) {
                $colClass .= " active-day";
            }
            ?>
            <div class="<?= $colClass ?>">
                <div class="attack-week-plot">
                    <div
                        class="<?= $barClass ?>"
                        style="height: <?= htmlspecialchars((string) $percent) ?>%;"
                        title="<?= htmlspecialchars($labels[$index] . ' ' . $dates[$index] . ': ' . $value . ' event' . ($value === 1 ? '' : 's')) ?>">
                    </div>
                </div>
                <div class="attack-week-day"><?= htmlspecialchars($labels[$index]) ?></div>
                <div class="attack-week-date"><?= htmlspecialchars($dates[$index]) ?></div>
            </div>
        <?php endforeach; ?>

        <?php if (!$hasAnyData): ?>
            <div class="attack-week-empty">No activity this week</div>
        <?php endif; ?>
    </div>
    <?php
    return ob_get_clean();
}

function getTipLibrary(): array
{
    return [
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
}

function getTipsForDisplay(string $query = "", bool $shuffle = false): array
{
    $tips = getTipLibrary()["home"];

    if ($shuffle) {
        shuffle($tips);
    }

    if ($query !== "") {
        $queryLower = strtolower($query);
        $tips = array_values(array_filter($tips, function ($tip) use ($queryLower) {
            return str_contains(strtolower($tip), $queryLower);
        }));
    }

    if ($query === "") {
        return array_slice($tips, 0, 3);
    }

    return $tips;
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
$attackChartHtml = renderAttackWeekChart(
    $attackMetrics["series"],
    $attackMetrics["labels"],
    $attackMetrics["dates"]
);

$alertCount = count($recentVulns);
$threatScore = getThreatScore($alertCount);
$passwordHealth = "Strong";
$feedStatusText = ($feedOnline || $advisoryOnline) ? "Live Feed Online" : "Feed Offline";
$liveStatusClass = ($feedOnline || $advisoryOnline) ? "live-status-bar" : "live-status-bar offline";

$displayTips = getTipsForDisplay($tipsSearchQuery, $shuffleTips);
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
                <a class="dash-nav-item active" href="homepage.php">Home</a>
                <a class="dash-nav-item" href="password_checker.php">Password Check</a>
                <a class="dash-nav-item" href="password_generator.php">Password Gen</a>
                <a class="dash-nav-item" href="vault.php">Vault</a>
                <a class="dash-nav-item" href="phishing_toolkit.php">Phishing Toolkit</a>
                <a class="dash-nav-item" href="about.php">About Me</a>
            </nav>

            <div class="dash-sidebar-spacer"></div>

            <a class="dash-nav-item" href="security_settings.php">Security Settings</a>
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
                        <div class="<?= $liveStatusClass ?>">
                            <span class="live-status-left">
                                <span class="status-dot"></span>
                                <span><?= htmlspecialchars($feedStatusText) ?></span>
                            </span>

                            <span class="live-status-divider"></span>

                            <span class="live-status-right">Loaded: <?= htmlspecialchars($lastLoadedText) ?></span>
                        </div>

                        <a class="refresh-btn" href="homepage.php?refresh=1">Refresh Feed</a>
                    </div>

                    <div class="feed-warning<?= trim($feedError) === '' ? ' hidden-warning' : '' ?>">
                        <?= htmlspecialchars(trim($feedError)) ?>
                    </div>

                    <div class="news-list">
                        <?php foreach ($newsItems as $item): ?>
                            <a class="news-item live-news news-link-card" href="<?= htmlspecialchars($item["link"]) ?>" target="_blank" rel="noopener noreferrer">
                                <div class="news-head"><?= safeText($item["title"]) ?></div>
                                <div class="news-sub"><?= safeText($item["summary"]) ?></div>
                                <div class="news-meta">
                                    <?= safeText($item["meta"]) ?>
                                    <?php if (!empty($item["date"])): ?>
                                        <span class="news-date"><?= safeText($item["date"]) ?></span>
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
                            <span>Security Events</span>
                        </div>

                        <?= $attackChartHtml ?>
                    </div>

                    <div class="attack-live-stats">
                        <div class="attack-mini-card">
                            <span class="attack-mini-label">Today</span>
                            <span class="attack-mini-value"><?= (int) $attackMetrics["currentCount"] ?></span>
                        </div>

                        <div class="attack-mini-card">
                            <span class="attack-mini-label">This Week</span>
                            <span class="attack-mini-value"><?= (int) $attackMetrics["weekCount"] ?></span>
                        </div>
                    </div>

                    <div class="chart-meta">
                        Latest: <?= htmlspecialchars($attackMetrics["latestType"]) ?>
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

                    <form class="quick-tips-bar" method="get" action="homepage.php">
                        <div class="tips-search-wrapper">
                            <input
                                type="text"
                                name="tips"
                                class="tips-search-input"
                                placeholder="Search tips like MFA, phishing, passwords..."
                                value="<?= htmlspecialchars($tipsSearchQuery) ?>">
                        </div>

                        <button type="submit" class="refresh-btn">Search</button>
                        <a class="refresh-btn" href="homepage.php?shuffle=1">New Tips</a>

                        <?php if ($tipsSearchQuery !== ""): ?>
                            <a class="refresh-btn secondary-btn" href="homepage.php">Clear</a>
                        <?php endif; ?>
                    </form>

                    <div class="tips-list">
                        <?php if (!empty($displayTips)): ?>
                            <?php foreach ($displayTips as $tip): ?>
                                <div class="tip-box"><?= htmlspecialchars($tip) ?></div>
                            <?php endforeach; ?>
                        <?php else: ?>
                            <div class="empty-state">
                                No tips matched your search.
                            </div>
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
