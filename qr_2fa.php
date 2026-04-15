<?php
session_start();

if (!isset($_SESSION["user_id"])) {
    http_response_code(403);
    exit("Forbidden");
}

$secret = (string) ($_SESSION["pending_twofa_secret"] ?? '');
if ($secret === '') {
    http_response_code(404);
    exit("No pending 2FA secret found.");
}

$username = (string) ($_SESSION["pending_2fa_username"] ?? $_SESSION["user_username"] ?? 'user');
$userId = (int) ($_SESSION["user_id"] ?? 0);

require_once __DIR__ . '/vendor/autoload.php';

use BaconQrCode\Renderer\ImageRenderer;
use BaconQrCode\Renderer\Image\GdImageBackEnd;
use BaconQrCode\Renderer\RendererStyle\RendererStyle;
use BaconQrCode\Writer;

$issuerRaw = 'Security Dashboard';
$accountRaw = $username !== '' ? $username : ('user-' . $userId);

$label = rawurlencode($issuerRaw . ':' . $accountRaw);

$otpauthUri = 'otpauth://totp/' . $label
    . '?secret=' . rawurlencode($secret)
    . '&issuer=' . rawurlencode($issuerRaw)
    . '&algorithm=SHA256'
    . '&digits=6'
    . '&period=30';

header('Content-Type: image/png');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');

$renderer = new ImageRenderer(
    new RendererStyle(280),
    new GdImageBackEnd()
);

$writer = new Writer($renderer);
echo $writer->writeString($otpauthUri);
exit;