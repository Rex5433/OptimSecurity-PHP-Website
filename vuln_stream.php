<?php
session_start();

header("Content-Type: application/json");
header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Pragma: no-cache");
header("Expires: 0");

if (!isset($_SESSION["user_id"])) {
    http_response_code(401);
    echo json_encode(["error" => "Unauthorized"]);
    exit;
}

require_once __DIR__ . "/attack_helpers.php";
require_once __DIR__ . "/db.php";

$userId = (int) ($_SESSION["user_id"] ?? 0);

$kevUrl = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
$advisoriesUrl = "https://www.cisa.gov/news-events/cybersecurity-advisories";

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
    $action = strtolower((string) ($requiredAction ?? ""));

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
            "timeout" => 15,
            "header" => "User-Agent: SecurityDashboard/1.0\r\n"
        ]
    ]);

    return @file_get_contents($url, false, $context);
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

function extractPublishedDateFromHtml(string $html): string
{
    if ($html === "") {
        return "";
    }

    libxml_use_internal_errors(true);

    $dom = new DOMDocument();
    @$dom->loadHTML($html);
    $xpath = new DOMXPath($dom);

    $metaQueries = [
        '//meta[@property="article:published_time"]/@content',
        '//meta[@name="article:published_time"]/@content',
        '//meta[@property="og:published_time"]/@content',
        '//meta[@name="publish-date"]/@content',
        '//meta[@name="published_time"]/@content',
        '//meta[@itemprop="datePublished"]/@content'
    ];

    foreach ($metaQueries as $query) {
        $nodes = $xpath->query($query);
        if ($nodes && $nodes->length > 0) {
            $value = formatDateText($nodes->item(0)->nodeValue ?? "");
            if ($value !== "") {
                return $value;
            }
        }
    }

    $timeNodes = $xpath->query('//time[@datetime]');
    if ($timeNodes && $timeNodes->length > 0) {
        foreach ($timeNodes as $node) {
            $value = formatDateText($node->getAttribute("datetime"));
            if ($value !== "") {
                return $value;
            }
        }
    }

    $text = normalizeWhitespace(strip_tags($html));

    if (preg_match('/\b(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\.?\s+\d{1,2},\s+\d{4}\b/i', $text, $match)) {
        return formatDateText($match[0]);
    }

    return "";
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
        "recentActivity" => $recentActivity
    ];
}

$recentVulns = [];
$newsItems = [];
$feedError = "";
$feedOnline = false;
$advisoryOnline = false;

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

        $vulns = array_slice($vulns, 0, 4);

        foreach ($vulns as $vuln) {
            $vendor = trim((string) ($vuln["vendorProject"] ?? ""));
            $product = trim((string) ($vuln["product"] ?? ""));
            $summary = trim((string) ($vuln["shortDescription"] ?? "No description available."));
            $actionLabel = getActionLabel($vuln["requiredAction"] ?? "");
            $dateAdded = trim((string) ($vuln["dateAdded"] ?? ""));

            $displayTitle = ($vendor !== "" && $product !== "")
                ? $vendor . " / " . $product
                : (($vendor !== "") ? $vendor : (($product !== "") ? $product : "Unnamed Vulnerability"));

            $recentVulns[] = [
                "title" => $displayTitle,
                "summary" => $summary,
                "action" => $actionLabel,
                "dateAdded" => $dateAdded
            ];
        }
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

    $seenLinks = [];

    foreach ($matches as $match) {
        $href = html_entity_decode($match[1], ENT_QUOTES | ENT_HTML5);
        $title = normalizeWhitespace(strip_tags($match[2]));

        if (
            $title === "" ||
            strlen($title) <= 18 ||
            (
                !str_contains($href, "/news-events/alerts/") &&
                !str_contains($href, "/news-events/cybersecurity-advisories/")
            )
        ) {
            continue;
        }

        if (!str_starts_with($href, "http")) {
            $href = "https://www.cisa.gov" . $href;
        }

        if (isset($seenLinks[$href])) {
            continue;
        }
        $seenLinks[$href] = true;

        $articleHtml = fetchUrl($href);
        $dateText = $articleHtml !== false ? extractPublishedDateFromHtml($articleHtml) : "";

        $newsItems[] = [
            "title" => $title,
            "summary" => "Live update from CISA Cybersecurity Alerts & Advisories.",
            "meta" => "Source: CISA",
            "date" => $dateText,
            "link" => $href
        ];

        if (count($newsItems) >= 4) {
            break;
        }
    }
} else {
    $feedError .= "Unable to load CISA advisories page. ";
}

if (empty($recentVulns)) {
    $recentVulns = [
        [
            "title" => "Feed Status / Unavailable",
            "summary" => "Live vulnerability data could not be loaded.",
            "action" => "Retry later",
            "dateAdded" => ""
        ]
    ];
}

if (empty($newsItems)) {
    $newsItems = [
        [
            "title" => "Live security updates unavailable",
            "summary" => "Live update from CISA Cybersecurity Alerts & Advisories.",
            "meta" => "Source: CISA",
            "date" => "",
            "link" => "#"
        ]
    ];
}

$liveActivity = buildLiveActivity($pdo, $userId);

echo json_encode([
    "newsItems" => $newsItems,
    "recentVulns" => $recentVulns,
    "threatScore" => getThreatScore(count($recentVulns)),
    "alertCount" => count($recentVulns),
    "feedOnline" => $feedOnline,
    "advisoryOnline" => $advisoryOnline,
    "feedError" => trim($feedError),

    "liveSuccessSeries" => $liveActivity["successSeries"],
    "liveFailedSeries" => $liveActivity["failedSeries"],
    "liveLabels" => $liveActivity["labels"],
    "liveDates" => $liveActivity["dates"],
    "todaySuccess" => $liveActivity["todaySuccess"],
    "todayFailed" => $liveActivity["todayFailed"],
    "weekSuccess" => $liveActivity["weekSuccess"],
    "weekFailed" => $liveActivity["weekFailed"],
    "totalAttempts" => $liveActivity["totalAttempts"],
    "successRate" => $liveActivity["successRate"],
    "recentActivity" => $liveActivity["recentActivity"]
]);
