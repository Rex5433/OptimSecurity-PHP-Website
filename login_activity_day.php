<?php
session_start();

header("Content-Type: application/json");
header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Pragma: no-cache");
header("Expires: 0");

if (!isset($_SESSION["user_id"])) {
    http_response_code(401);
    echo json_encode([
        "label" => "Unauthorized",
        "total" => 0,
        "rows" => []
    ]);
    exit;
}

require_once __DIR__ . "/db.php";

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

function buildLocationText(array $row): string
{
    $direct = trim((string) ($row["location"] ?? ""));
    if ($direct !== "") {
        return $direct;
    }

    $parts = [];
    foreach (["city", "region", "country"] as $key) {
        $value = trim((string) ($row[$key] ?? ""));
        if ($value !== "") {
            $parts[] = $value;
        }
    }

    return !empty($parts) ? implode(", ", $parts) : "Unknown";
}

$day = $_GET["day"] ?? "";
if (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $day)) {
    http_response_code(400);
    echo json_encode([
        "label" => "Invalid Day",
        "total" => 0,
        "rows" => []
    ]);
    exit;
}

$map = getLoginActivityColumnMap($pdo);

if ($map["timestamp"] === null || $map["user_id"] === null) {
    echo json_encode([
        "label" => date("D M j", strtotime($day)),
        "total" => 0,
        "rows" => []
    ]);
    exit;
}

$dayStart = $day . " 00:00:00";
$dayEnd = date("Y-m-d 00:00:00", strtotime($day . " +1 day"));

$selectParts = [];

if ($map["ip"] !== null) {
    $selectParts[] = quoteIdent($map["ip"]) . ' AS "ip"';
} else {
    $selectParts[] = 'NULL AS "ip"';
}

if ($map["location"] !== null) {
    $selectParts[] = quoteIdent($map["location"]) . ' AS "location"';
} else {
    $selectParts[] = 'NULL AS "location"';
}

if ($map["city"] !== null) {
    $selectParts[] = quoteIdent($map["city"]) . ' AS "city"';
} else {
    $selectParts[] = 'NULL AS "city"';
}

if ($map["region"] !== null) {
    $selectParts[] = quoteIdent($map["region"]) . ' AS "region"';
} else {
    $selectParts[] = 'NULL AS "region"';
}

if ($map["country"] !== null) {
    $selectParts[] = quoteIdent($map["country"]) . ' AS "country"';
} else {
    $selectParts[] = 'NULL AS "country"';
}

if ($map["event_type"] !== null) {
    $selectParts[] = quoteIdent($map["event_type"]) . ' AS "event_type"';
} else {
    $selectParts[] = 'NULL AS "event_type"';
}

if ($map["user_agent"] !== null) {
    $selectParts[] = quoteIdent($map["user_agent"]) . ' AS "user_agent"';
} else {
    $selectParts[] = 'NULL AS "user_agent"';
}

$selectParts[] = quoteIdent($map["timestamp"]) . ' AS "created_at"';

$sql = "
    SELECT " . implode(", ", $selectParts) . "
    FROM public.login_activity
    WHERE " . quoteIdent($map["timestamp"]) . " >= ?
      AND " . quoteIdent($map["timestamp"]) . " < ?
      AND " . quoteIdent($map["user_id"]) . " = ?
    ORDER BY " . quoteIdent($map["timestamp"]) . " DESC
    LIMIT 25
";

$stmt = $pdo->prepare($sql);
$stmt->execute([
    $dayStart,
    $dayEnd,
    $_SESSION["user_id"]
]);

$results = $stmt->fetchAll(PDO::FETCH_ASSOC) ?: [];

$rows = [];
foreach ($results as $row) {
    $rows[] = [
        "ip" => trim((string) ($row["ip"] ?? "")) !== "" ? (string) $row["ip"] : "N/A",
        "location" => buildLocationText($row),
        "event_type" => trim((string) ($row["event_type"] ?? "")) !== "" ? (string) $row["event_type"] : "Login Activity",
        "created_at" => !empty($row["created_at"])
            ? date("M j, Y g:i A", strtotime((string) $row["created_at"]))
            : "N/A",
        "user_agent" => trim((string) ($row["user_agent"] ?? "")) !== "" ? (string) $row["user_agent"] : "N/A"
    ];
}

echo json_encode([
    "label" => date("D M j", strtotime($day)),
    "total" => count($rows),
    "rows" => $rows
]);
