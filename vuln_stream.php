<?php
session_start();

require_once __DIR__ . "/attack_helpers.php";
require_once __DIR__ . "/db.php";

header("Content-Type: application/json");
header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Pragma: no-cache");
header("Expires: 0");

date_default_timezone_set("America/Chicago");

$userId = (int) ($_SESSION["user_id"] ?? 0);

$kevUrl = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
$advisoriesUrl = "https://www.cisa.gov/news-events/cybersecurity-advisories";
$sansFeedUrl = "https://isc.sans.edu/rssfeed_full.xml";
$unit42Url = "https://unit42.paloaltonetworks.com/";

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

function buildAttackMetrics(PDO $pdo, int $userId): array
{
    $series = [];
    $labels = [];
    $dates = [];
    $weekCount = 0;
    $latestType = "No Recent Activity";

    for ($i = 6; $i >= 0; $i--) {
        $dayTs = strtotime("-$i days");
        $dayStart = date("Y-m-d 00:00:00", $dayTs);
        $dayEnd = date("Y-m-d 23:59:59", $dayTs);

        $stmt = $pdo->prepare("
            SELECT COUNT(*)
            FROM public.login_activity
            WHERE user_id = ?
              AND created_at BETWEEN ? AND ?
              AND LOWER(TRIM(COALESCE(event_type, ''))) = ?
        ");

        $stmt->execute([
            $userId,
            $dayStart,
            $dayEnd,
            "successful_login"
        ]);

        $count = (int) $stmt->fetchColumn();

        $series[] = $count;
        $labels[] = date("D", $dayTs);
        $dates[] = date("M j", $dayTs);
        $weekCount += $count;
    }

    $latestStmt = $pdo->prepare("
        SELECT created_at
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

    $latestCreatedAt = $latestStmt->fetchColumn();
    if ($latestCreatedAt !== false) {
        $latestType = "Successful Login";
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
        "latestType" => $latestType
    ];
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

            if (preg_match('/(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\.?\s+\d{1,2},\s+\d{4}/i', strip_tags($match[2]), $dateMatch)) {
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

$feedOnline = $feedOnline || !empty($sansItems) || !empty($unit42Items);
$advisoryOnline = $advisoryOnline || !empty($sansItems) || !empty($unit42Items);

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
            "summary" => "Could not load titled security updates right now.",
            "meta" => "Fallback mode",
            "date" => "",
            "link" => "#"
        ]
    ];
}

if ($pdo instanceof PDO && $userId > 0) {
    $attackMetrics = buildAttackMetrics($pdo, $userId);
} else {
    $attackMetrics = [
        "series" => [0, 0, 0, 0, 0, 0, 0],
        "labels" => ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"],
        "dates" => ["", "", "", "", "", "", ""],
        "currentCount" => 0,
        "weekCount" => 0,
        "latestType" => "No Recent Activity"
    ];
}

echo json_encode([
    "newsItems" => array_map(function ($item) {
        unset($item["timestamp"]);
        return $item;
    }, $newsItems),
    "recentVulns" => $recentVulns,
    "threatScore" => getThreatScore(count($recentVulns)),
    "alertCount" => count($recentVulns),
    "feedOnline" => $feedOnline,
    "advisoryOnline" => $advisoryOnline,
    "feedError" => trim($feedError),
    "attackSeries" => $attackMetrics["series"],
    "attackLabels" => $attackMetrics["labels"],
    "attackDates" => $attackMetrics["dates"],
    "attackLatestType" => $attackMetrics["latestType"],
    "attackCurrentCount" => $attackMetrics["currentCount"],
    "attackWeekCount" => $attackMetrics["weekCount"]
]);
