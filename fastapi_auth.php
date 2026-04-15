<?php
declare(strict_types=1);

function getCloudRunIdToken(string $audience): string
{
    $metadataUrl =
        'http://metadata/computeMetadata/v1/instance/service-accounts/default/identity'
        . '?audience=' . rawurlencode($audience)
        . '&format=full';

    $ch = curl_init($metadataUrl);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 10);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Metadata-Flavor: Google',
    ]);

    $token = curl_exec($ch);

    if ($token === false) {
        $error = curl_error($ch);
        curl_close($ch);
        throw new Exception('Failed to get ID token: ' . $error);
    }

    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($httpCode !== 200 || trim($token) === '') {
        throw new Exception('Metadata server returned an invalid ID token response.');
    }

    return trim($token);
}
?>
