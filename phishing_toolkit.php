<?php
session_start();
include __DIR__ . "/db.php";
require_once __DIR__ . "/attack_helpers.php";

if (!isset($_SESSION["user_id"])) {
    header("Location: login.php");
    exit;
}

$analysisMessage = "";
$analysisSeverity = "low";
$analysisDetails = [];
$analysisScore = 0;
$legitimacyDetails = [];

function safeText($value, $default = "")
{
    $value = trim((string) ($value ?? ""));
    return $value !== "" ? htmlspecialchars($value, ENT_QUOTES, "UTF-8") : $default;
}

function detectSuspiciousInput(string $text): bool
{
    return preg_match('/<script|onerror=|javascript:|union\s+select|drop\s+table|sleep\s*\(|benchmark\s*\(/i', $text) === 1;
}

function normalizeHost(string $host): string
{
    return strtolower(trim($host, ". \t\n\r\0\x0B<>[]()\"'"));
}

function extractDomainFromEmail(string $email): string
{
    $email = strtolower(trim($email));
    if (strpos($email, '@') === false) {
        return "";
    }
    return normalizeHost(substr(strrchr($email, '@'), 1));
}

function domainMatches(string $domain, string $trusted): bool
{
    $domain = normalizeHost($domain);
    $trusted = normalizeHost($trusted);

    if ($domain === '' || $trusted === '') {
        return false;
    }

    return $domain === $trusted || str_ends_with($domain, '.' . $trusted);
}

function getTrustedBrandDomains(): array
{
    return [
        'microsoft' => ['microsoft.com', 'microsoftonline.com', 'office.com', 'outlook.com', 'live.com', 'sharepointonline.com', 'windows.net'],
        'office 365' => ['microsoft.com', 'microsoftonline.com', 'office.com', 'outlook.com', 'office365.com'],
        'outlook' => ['outlook.com', 'microsoft.com', 'microsoftonline.com', 'live.com'],
        'azure' => ['microsoft.com', 'microsoftonline.com', 'azure.com', 'windows.net'],
        'onedrive' => ['microsoft.com', 'onedrive.com', 'sharepointonline.com'],
        'paypal' => ['paypal.com', 'paypalobjects.com'],
        'amazon' => ['amazon.com', 'amazonaws.com', 'amazonpay.com'],
        'aws' => ['amazonaws.com', 'aws.amazon.com'],
        'google' => ['google.com', 'accounts.google.com', 'gmail.com', 'googlemail.com', 'youtube.com', 'withgoogle.com', 'notifications.google.com', 'bounces.google.com'],
        'gmail' => ['gmail.com', 'google.com', 'accounts.google.com', 'googlemail.com'],
        'apple' => ['apple.com', 'icloud.com', 'me.com'],
        'icloud' => ['icloud.com', 'apple.com', 'me.com'],
        'github' => ['github.com', 'githubusercontent.com', 'githubapp.com', 'githubassets.com', 'github.io', 'noreply.github.com'],
        'bank of america' => ['bankofamerica.com'],
        'chase' => ['chase.com'],
        'wells fargo' => ['wellsfargo.com'],
        'citibank' => ['citi.com', 'citibank.com'],
        'irs' => ['irs.gov'],
        'fedex' => ['fedex.com'],
        'ups' => ['ups.com'],
        'dhl' => ['dhl.com'],
        'usps' => ['usps.com'],
        'netflix' => ['netflix.com'],
        'dropbox' => ['dropbox.com'],
        'docusign' => ['docusign.net', 'docusign.com'],
        'linkedin' => ['linkedin.com'],
        'facebook' => ['facebook.com', 'fb.com', 'meta.com', 'facebookmail.com'],
        'instagram' => ['instagram.com', 'facebookmail.com', 'meta.com'],
        'twitter' => ['twitter.com', 'x.com'],
        'x' => ['x.com', 'twitter.com'],
        'whatsapp' => ['whatsapp.com', 'facebookmail.com', 'meta.com'],
        'coinbase' => ['coinbase.com'],
        'binance' => ['binance.com']
    ];
}

function findMentionedBrands(string $content): array
{
    $brands = array_keys(getTrustedBrandDomains());
    $matched = [];

    foreach ($brands as $brand) {
        if (stripos($content, $brand) !== false) {
            $matched[] = $brand;
        }
    }

    return array_values(array_unique($matched));
}

function domainLooksLegitForBrand(string $brand, string $domain): bool
{
    $map = getTrustedBrandDomains();
    $domain = normalizeHost($domain);

    if ($domain === '' || !isset($map[$brand])) {
        return false;
    }

    foreach ($map[$brand] as $trusted) {
        if (domainMatches($domain, $trusted)) {
            return true;
        }
    }

    return false;
}

function parseAuthenticationSignals(string $content): array
{
    $riskFindings = [];
    $legitFindings = [];

    $spfPass = preg_match('/\bspf\s*=\s*pass\b/i', $content) === 1;
    $dkimPass = preg_match('/\bdkim\s*=\s*pass\b/i', $content) === 1;
    $dmarcPass = preg_match('/\bdmarc\s*=\s*pass\b/i', $content) === 1;

    $spfFail = preg_match('/\bspf\s*=\s*(fail|softfail)\b/i', $content) === 1;
    $dkimFail = preg_match('/\bdkim\s*=\s*(fail|none)\b/i', $content) === 1;
    $dmarcFail = preg_match('/\bdmarc\s*=\s*fail\b/i', $content) === 1;

    if ($spfPass) {
        $legitFindings[] = [
            'label' => 'SPF passed',
            'severity' => 'low',
            'detail' => 'The sender appears authorised to send mail for the domain.'
        ];
    }

    if ($dkimPass) {
        $legitFindings[] = [
            'label' => 'DKIM passed',
            'severity' => 'low',
            'detail' => 'The message signature validated successfully.'
        ];
    }

    if ($dmarcPass) {
        $legitFindings[] = [
            'label' => 'DMARC passed',
            'severity' => 'low',
            'detail' => 'Domain alignment checks passed for the message.'
        ];
    }

    if ($spfFail) {
        $riskFindings[] = [
            'label' => 'SPF authentication failed',
            'severity' => 'high',
            'detail' => 'SPF failed or soft-failed, so the sender may not be authorised for the domain.'
        ];
    }

    if ($dkimFail) {
        $riskFindings[] = [
            'label' => 'DKIM authentication failed',
            'severity' => 'high',
            'detail' => 'DKIM failed or was absent, so the message signature did not validate.'
        ];
    }

    if ($dmarcFail) {
        $riskFindings[] = [
            'label' => 'DMARC authentication failed',
            'severity' => 'high',
            'detail' => 'DMARC failed, which is a strong spoofing signal.'
        ];
    }

    return [
        'risk' => $riskFindings,
        'legit' => $legitFindings,
        'passes' => (int) $spfPass + (int) $dkimPass + (int) $dmarcPass,
        'has_failure' => $spfFail || $dkimFail || $dmarcFail,
        'spf_pass' => $spfPass,
        'dkim_pass' => $dkimPass,
        'dmarc_pass' => $dmarcPass,
    ];
}

function getTrustedSenderContext(string $content, array $mentionedBrands, array $auth): array
{
    $fromDomain = '';
    $displayName = '';
    $replyDomain = '';
    $returnPathDomain = '';
    $dkimDomain = '';
    $dmarcFromDomain = '';
    $trustedBrandMatches = [];
    $senderTrustedPlatform = false;

    if (preg_match('/From:\s*"?([^"<\n]+)"?\s*<([^>]+)>/i', $content, $fromMatch)) {
        $displayName = strtolower(trim($fromMatch[1]));
        $fromAddr = strtolower(trim($fromMatch[2]));
        $fromDomain = extractDomainFromEmail($fromAddr);
    } elseif (preg_match('/From:\s*[^\n<]*<?([^>\s\n]+@[^>\s\n]+)>?/i', $content, $fromSimpleMatch)) {
        $fromDomain = extractDomainFromEmail($fromSimpleMatch[1]);
    }

    if (preg_match('/Reply-To:\s*[^\n<]*<?([^>\s\n]+@[^>\s\n]+)>?/i', $content, $replyMatch)) {
        $replyDomain = extractDomainFromEmail($replyMatch[1]);
    }

    if (preg_match('/Return-Path:\s*<([^>]+)>/i', $content, $returnPathMatch)) {
        $returnPathDomain = extractDomainFromEmail($returnPathMatch[1]);
    }

    if (preg_match('/\bdkim=pass\b.*?\bheader\.i=@([a-z0-9.\-]+)/is', $content, $dkimMatch)) {
        $dkimDomain = normalizeHost($dkimMatch[1]);
    }

    if (preg_match('/\bdmarc=pass\b.*?\bheader\.from=([a-z0-9.\-]+)/is', $content, $dmarcMatch)) {
        $dmarcFromDomain = normalizeHost($dmarcMatch[1]);
    }

    if ($fromDomain !== '') {
        foreach (getTrustedBrandDomains() as $brand => $trustedDomains) {
            if (
                domainLooksLegitForBrand($brand, $fromDomain) ||
                ($dkimDomain !== '' && domainLooksLegitForBrand($brand, $dkimDomain)) ||
                ($dmarcFromDomain !== '' && domainLooksLegitForBrand($brand, $dmarcFromDomain)) ||
                ($returnPathDomain !== '' && domainLooksLegitForBrand($brand, $returnPathDomain))
            ) {
                $senderTrustedPlatform = true;

                if (
                    stripos($content, $brand) !== false ||
                    stripos($displayName, $brand) !== false ||
                    in_array($brand, $mentionedBrands, true)
                ) {
                    $trustedBrandMatches[] = $brand;
                }
            }
        }
    }

    $trustedBrandMatches = array_values(array_unique($trustedBrandMatches));

    $strongAlignedAuth = (
        !$auth['has_failure'] &&
        $auth['passes'] >= 3 &&
        $fromDomain !== '' &&
        (
            ($dkimDomain !== '' && domainMatches($fromDomain, $dkimDomain)) ||
            ($dmarcFromDomain !== '' && domainMatches($fromDomain, $dmarcFromDomain))
        )
    );

    $confirmedLegit = $strongAlignedAuth && ($senderTrustedPlatform || !empty($trustedBrandMatches));

    return [
        'from_domain' => $fromDomain,
        'display_name' => $displayName,
        'reply_domain' => $replyDomain,
        'return_path_domain' => $returnPathDomain,
        'dkim_domain' => $dkimDomain,
        'dmarc_from_domain' => $dmarcFromDomain,
        'trusted_brand_matches' => $trustedBrandMatches,
        'trusted_platform' => $senderTrustedPlatform,
        'strong_aligned_auth' => $strongAlignedAuth,
        'confirmed_legit' => $confirmedLegit,
    ];
}

function runAllChecks(string $content): array
{
    $riskFindings = [];
    $legitFindings = [];

    $auth = parseAuthenticationSignals($content);
    $legitFindings = array_merge($legitFindings, $auth['legit']);
    $riskFindings = array_merge($riskFindings, $auth['risk']);

    $brands = findMentionedBrands($content);
    $trustedSender = getTrustedSenderContext($content, $brands, $auth);

    if ($trustedSender['confirmed_legit']) {
        $brandText = !empty($trustedSender['trusted_brand_matches'])
            ? implode(', ', $trustedSender['trusted_brand_matches'])
            : $trustedSender['from_domain'];

        $legitFindings[] = [
            'label' => 'Trusted sender identified',
            'severity' => 'low',
            'detail' => 'Sender domain and authentication signals align with a trusted source: ' . $brandText
        ];
    }

    $urgencyMatches = [];
    $urgencyTerms = [
        'urgent', 'immediately', 'asap', 'final warning', 'act now',
        'action required', 'last chance', 'expire[sd]?', 'within 24 hours',
        'within 48 hours', 'respond now', 'failure to act', 'limited time',
        'your account will be (closed|terminated|suspended|disabled)',
        'legal action', 'law enforcement', 'arrest warrant'
    ];

    foreach ($urgencyTerms as $term) {
        if (preg_match('/\b' . $term . '\b/i', $content, $m)) {
            $urgencyMatches[] = $m[0];
        }
    }

    if ($urgencyMatches && !$trustedSender['confirmed_legit']) {
        $sev = count($urgencyMatches) >= 3 ? 'high' : 'medium';
        $riskFindings[] = [
            'label' => 'Urgency / threat language',
            'severity' => $sev,
            'detail' => 'Matched: ' . implode(', ', array_unique($urgencyMatches))
        ];
    }

    $hasCredentialLanguage = preg_match('/verify your (account|identity|email|details)|confirm your (password|credentials|email)|
        login now|sign in now|reset your password|enter your (password|credentials|pin|ssn|social security)|
        provide your (details|information|credentials)|update your (payment|billing|card)|
        your (password|pin|card number) (has expired|is required|needs to be updated)/ix', $content) === 1;

    if ($hasCredentialLanguage && !$trustedSender['confirmed_legit']) {
        $riskFindings[] = [
            'label' => 'Credential or sensitive data request',
            'severity' => 'high',
            'detail' => 'Email requests login credentials, passwords, PINs, or personal details.'
        ];
    }

    if (preg_match('/bank alert|payment (failed|declined|overdue)|unpaid invoice|
        refund (pending|available|issued)|gift card|wire transfer|billing issue|
        your (card|payment method) (was|has been) (declined|charged)|
        cryptocurrency|bitcoin|crypto payment|Western Union|MoneyGram|
        you (have won|are entitled to|are selected for) .{0,40}(prize|award|reward|lottery)/ix', $content)) {
        $riskFindings[] = [
            'label' => 'Financial lure or payment scam',
            'severity' => 'high',
            'detail' => 'Content references financial transactions, prizes, or payment demands.'
        ];
    }

    $hasAccountThreatLanguage = preg_match('/account (suspended|locked|disabled|terminated|compromised|flagged)|
        security alert|unusual (activity|sign.?in|login)|suspicious (activity|access)|
        unauthorized (access|login|sign.?in)|someone tried to (access|sign into)|
        your account (has been|will be) (suspended|locked|disabled|closed)/ix', $content) === 1;

    if ($hasAccountThreatLanguage && !$trustedSender['confirmedLegit'] ?? false) {
        // unreachable safeguard
    }

    if ($hasAccountThreatLanguage && !$trustedSender['confirmed_legit']) {
        $riskFindings[] = [
            'label' => 'Account threat or security alert',
            'severity' => 'medium',
            'detail' => 'Claims of account compromise or suspension to create panic.'
        ];
    } elseif ($hasAccountThreatLanguage && $trustedSender['confirmed_legit']) {
        $legitFindings[] = [
            'label' => 'Legitimate security/account notice language',
            'severity' => 'low',
            'detail' => 'Security-account wording appears in a strongly authenticated message from a trusted sender.'
        ];
    }

    $hasCallToAction = preg_match('/click here|open this link|visit (now|this link|the link)|
        review now|tap (below|here)|download (now|here)|view (attachment|document)|
        access (your account|here)|confirm (here|now|your account)|disconnect email/ix', $content) === 1;

    if ($hasCallToAction && !$trustedSender['confirmed_legit']) {
        $riskFindings[] = [
            'label' => 'Manipulative call-to-action',
            'severity' => 'medium',
            'detail' => 'Pressures the reader to click a link or open an attachment immediately.'
        ];
    } elseif ($hasCallToAction && $trustedSender['confirmed_legit']) {
        $legitFindings[] = [
            'label' => 'Normal action link in trusted message',
            'severity' => 'low',
            'detail' => 'The message includes an action link, but the sender is strongly authenticated and trusted.'
        ];
    }

    if (preg_match('/mfa code|verification code|one.?time (code|password|pin)|
        2fa code|authenticator code|otp|passcode sent to|enter the code|
        do not share (this|your) code/ix', $content) && !$trustedSender['confirmed_legit']) {
        $riskFindings[] = [
            'label' => 'MFA or one-time code request',
            'severity' => 'high',
            'detail' => 'Requests or references multi-factor authentication codes.'
        ];
    }

    if (preg_match('/attached (file|document|invoice|receipt)|open (attachment|the attached)|
        download (the attached|attached file|this file)|see attached|
        \.(exe|zip|js|vbs|bat|cmd|docm|xlsm|lnk|iso|rar|7z|ps1)\b/ix', $content)) {
        $sev = preg_match('/\.(exe|js|vbs|bat|cmd|ps1|lnk)\b/i', $content) ? 'high' : 'medium';
        $riskFindings[] = [
            'label' => 'Attachment lure' . ($sev === 'high' ? ' (dangerous file type)' : ''),
            'severity' => $sev,
            'detail' => 'References file attachments; executable or script extensions are especially risky.'
        ];
    }

    if (!empty($brands) && ($hasCredentialLanguage || !empty($urgencyMatches)) && !$trustedSender['confirmed_legit']) {
        $riskFindings[] = [
            'label' => 'Brand-related social engineering',
            'severity' => 'medium',
            'detail' => 'Mentions brand(s) alongside urgency or credential requests: ' . implode(', ', $brands)
        ];
    }

    preg_match_all('/https?:\/\/[^\s\'"<>]+/i', $content, $urlMatches);
    $urls = $urlMatches[0] ?? [];
    preg_match_all('/href=["\']?(https?:\/\/[^\s\'"<>]+)/i', $content, $hrefMatches);
    $urls = array_unique(array_merge($urls, $hrefMatches[1] ?? []));

    if (!empty($urls)) {
        $urlIssues = [];
        $legitUrlNotes = [];

        $suspiciousTlds = ['\.tk$', '\.ml$', '\.ga$', '\.cf$', '\.gq$', '\.top$', '\.xyz$', '\.click$', '\.loan$', '\.work$', '\.date$', '\.racing$', '\.download$', '\.win$', '\.bid$'];
        $shorteners = ['bit\.ly', 'tinyurl\.com', 'goo\.gl', 't\.co', 'ow\.ly', 'buff\.ly', 'rebrand\.ly', 'tiny\.cc', 'is\.gd', 'cutt\.ly', 'shorturl\.at', 'rb\.gy', 'bl\.ink'];
        $lookalikeBrands = [
            'paypa[l1]', 'payp4l', 'arnazon', 'amaz[o0]n', 'g[o0][o0]gle',
            'micr[o0]s[o0]ft', 'microsofl', 'app1e', 'appl[e3]\.(?!com)',
            'faceb[o0][o0]k', 'instagramm', 'linkedln', 'linked1n',
            'netf1ix', 'netfl1x', 'dropb[o0]x', 'doc[u0]sign',
            'githu[b8]', 'gitnub', 'g1thub'
        ];

        foreach ($urls as $url) {
            $parsed = parse_url($url);
            $host = normalizeHost((string) ($parsed['host'] ?? ''));
            $fullUrl = $url;

            if ($host === '') {
                continue;
            }

            $isTrustedBrandHost = false;
            foreach ($brands as $brand) {
                if (domainLooksLegitForBrand($brand, $host)) {
                    $isTrustedBrandHost = true;
                    break;
                }
            }

            if (preg_match('/^\d{1,3}(\.\d{1,3}){3}$/', $host)) {
                $urlIssues[] = "IP address used as domain ($host)";
            }

            foreach ($suspiciousTlds as $tld) {
                if (preg_match('/' . $tld . '/i', $host)) {
                    $urlIssues[] = "Suspicious TLD in URL: $host";
                    break;
                }
            }

            foreach ($shorteners as $s) {
                if (preg_match('/' . $s . '/i', $host)) {
                    $urlIssues[] = "URL shortener used ($host)";
                    break;
                }
            }

            foreach ($lookalikeBrands as $pattern) {
                if (preg_match('/' . $pattern . '/i', $host)) {
                    $urlIssues[] = "Lookalike brand domain: $host";
                    break;
                }
            }

            $parts = explode('.', $host);
            if (count($parts) >= 5 && !$isTrustedBrandHost) {
                $urlIssues[] = "Excessive subdomain depth in URL: $host";
            }

            if (preg_match('/%[0-9a-f]{2}/i', $url) && substr_count($url, '%') > 2) {
                $urlIssues[] = 'Heavy URL encoding detected';
            }

            if (preg_match('/\b(javascript|data):/i', $fullUrl)) {
                $urlIssues[] = 'Dangerous URI scheme detected';
            }

            if (!empty($parsed['port']) && !in_array((int) $parsed['port'], [80, 443, 8080, 8443], true)) {
                $urlIssues[] = 'Non-standard port in URL (' . (int) $parsed['port'] . ')';
            }

            if (($parsed['scheme'] ?? '') === 'http') {
                if ($isTrustedBrandHost) {
                    $urlIssues[] = "Insecure HTTP link for brand domain: $host";
                } else {
                    $urlIssues[] = "Insecure HTTP link used: $host";
                }
            }

            if ($isTrustedBrandHost && ($parsed['scheme'] ?? '') === 'https') {
                $legitUrlNotes[] = $host;
            }
        }

        if (!empty($urlIssues)) {
            $urlSeverity = count(array_unique($urlIssues)) >= 2 ? 'high' : 'medium';
            $riskFindings[] = [
                'label' => 'Suspicious URL(s) detected',
                'severity' => $urlSeverity,
                'detail' => implode('; ', array_unique($urlIssues))
            ];
        } elseif (!empty($legitUrlNotes)) {
            $legitFindings[] = [
                'label' => 'Trusted destination links',
                'severity' => 'low',
                'detail' => 'Links point to expected trusted domains over HTTPS: ' . implode(', ', array_unique($legitUrlNotes))
            ];
        }
    }

    $headerIssues = [];
    $fromDomain = $trustedSender['from_domain'];
    $replyDomain = $trustedSender['reply_domain'];
    $displayBrandMatches = [];

    if (preg_match('/From:\s*"?([^"<\n]+)"?\s*<([^>]+)>/i', $content, $fromMatch)) {
        $displayName = strtolower(trim($fromMatch[1]));

        foreach ($brands as $brand) {
            if (stripos($displayName, $brand) !== false) {
                $displayBrandMatches[] = $brand;
            }
        }

        foreach (array_unique($displayBrandMatches) as $brand) {
            if (!domainLooksLegitForBrand($brand, $fromDomain)) {
                if ($auth['has_failure'] || $hasCredentialLanguage || !empty($urgencyMatches)) {
                    $headerIssues[] = "Display name claims to be \"$brand\" but sender domain is \"$fromDomain\"";
                }
            } else {
                $legitFindings[] = [
                    'label' => 'Sender domain matches visible brand',
                    'severity' => 'low',
                    'detail' => "Display name and sender domain align for $brand ($fromDomain)."
                ];
            }
        }
    }

    if ($fromDomain !== '' && $replyDomain !== '' && $fromDomain !== $replyDomain) {
        $replyToSeverity = ($auth['has_failure'] || $hasCredentialLanguage || !empty($urgencyMatches)) ? 'medium' : 'low';
        if ($replyToSeverity === 'medium' && !$trustedSender['confirmed_legit']) {
            $headerIssues[] = "Reply-To domain ($replyDomain) differs from From domain ($fromDomain)";
        } else {
            $legitFindings[] = [
                'label' => 'Reply-To differs from From',
                'severity' => 'low',
                'detail' => "Reply-To uses $replyDomain while From uses $fromDomain. This can be normal for support or ticketing systems."
            ];
        }
    }

    if (preg_match('/X-Mailer:\s*(phpmailer|sendblaster|bombsquad|massmailer|massmail)/i', $content, $xm)) {
        $headerIssues[] = 'X-Mailer indicates bulk or automated mail tool: ' . $xm[1];
    }

    if (!empty($headerIssues)) {
        $riskFindings[] = [
            'label' => 'Email header anomalies',
            'severity' => $auth['has_failure'] ? 'high' : 'medium',
            'detail' => implode('; ', array_unique($headerIssues))
        ];
    }

    $encIssues = [];
    if (preg_match_all('/[A-Za-z0-9+\/]{40,}={0,2}/', $content, $b64)) {
        $validBase64 = array_filter($b64[0], function ($chunk) {
            $decoded = base64_decode($chunk, true);
            return $decoded !== false && preg_match('/[a-zA-Z]{4,}/', $decoded);
        });

        if (count($validBase64) >= 5 && !$trustedSender['confirmed_legit']) {
            $encIssues[] = 'Multiple base64-encoded blocks detected';
        }
    }

    if (preg_match('/xn--[a-z0-9\-]+\.[a-z]{2,}/i', $content)) {
        $encIssues[] = 'Punycode (IDN) domain detected';
    }

    if (preg_match_all('/&#\d+;/', $content, $entities) && count($entities[0]) > 8 && !$trustedSender['confirmed_legit']) {
        $encIssues[] = 'Extensive HTML entity encoding detected';
    }

    if (preg_match('/[\x{200F}\x{202E}\x{2066}\x{2067}\x{2068}\x{2069}]/u', $content)) {
        $encIssues[] = 'Unicode right-to-left override character detected';
    }

    if (!empty($encIssues)) {
        $riskFindings[] = [
            'label' => 'Content obfuscation or encoding tricks',
            'severity' => 'high',
            'detail' => implode('; ', $encIssues)
        ];
    }

    preg_match_all('/<a\s[^>]*href=["\']([^"\']+)["\'][^>]*>(.*?)<\/a>/is', $content, $anchors);
    $anchorIssues = [];
    foreach ($anchors[1] as $idx => $href) {
        $anchorText = strip_tags($anchors[2][$idx]);

        if (preg_match('/https?:\/\/(\S+)/i', $anchorText, $textUrl)) {
            $hrefHost = normalizeHost((string) (parse_url($href, PHP_URL_HOST) ?? ''));
            $anchorHost = normalizeHost((string) (parse_url($textUrl[0], PHP_URL_HOST) ?? ''));
            if ($hrefHost !== '' && $anchorHost !== '' && $hrefHost !== $anchorHost) {
                $anchorIssues[] = "Link text shows $anchorHost but href points to $hrefHost";
            }
        }

        foreach ($brands as $brand) {
            if (stripos($anchorText, $brand) !== false) {
                $hrefHost = normalizeHost((string) (parse_url($href, PHP_URL_HOST) ?? ''));
                if ($hrefHost !== '' && !domainLooksLegitForBrand($brand, $hrefHost)) {
                    $anchorIssues[] = "Link text mentions $brand but goes to $hrefHost";
                    break;
                }
            }
        }
    }

    if (!empty($anchorIssues)) {
        $riskFindings[] = [
            'label' => 'Mismatched link text vs destination',
            'severity' => 'high',
            'detail' => implode('; ', array_unique($anchorIssues))
        ];
    }

    $grammarFlags = [];
    if (preg_match('/dear (valued |esteemed )?(customer|user|member|client|account holder)\b/i', $content)) {
        $grammarFlags[] = 'Generic salutation ("Dear Customer") instead of a real name';
    }
    if (preg_match('/kindly (click|verify|update|confirm|provide)/i', $content)) {
        $grammarFlags[] = '"Kindly" phrasing can appear in phishing templates';
    }
    if (preg_match('/do the needful|revert back to us|at the earliest/i', $content)) {
        $grammarFlags[] = 'Non-idiomatic phrasing often seen in phishing templates';
    }
    if (!empty($grammarFlags) && !$trustedSender['confirmed_legit']) {
        $riskFindings[] = [
            'label' => 'Impersonation / template language signals',
            'severity' => 'low',
            'detail' => implode('; ', $grammarFlags)
        ];
    }

    return [
        'risk' => $riskFindings,
        'legit' => $legitFindings,
        'auth_passes' => $auth['passes'],
        'auth_failed' => $auth['has_failure'],
        'trusted_sender' => $trustedSender['confirmed_legit'],
        'strong_aligned_auth' => $trustedSender['strong_aligned_auth'],
    ];
}

function analyzePhishingContent(string $content): array
{
    $results = runAllChecks($content);
    $riskFindings = $results['risk'];
    $legitFindings = $results['legit'];

    if (
        $results['trusted_sender'] &&
        !$results['auth_failed'] &&
        $results['auth_passes'] >= 3 &&
        $results['strong_aligned_auth']
    ) {
        $legitFindings[] = [
            'label' => 'Verified trusted sender (strong)',
            'severity' => 'low',
            'detail' => 'SPF, DKIM, and DMARC all passed and aligned with a trusted sender domain.'
        ];

        return [
            'message' => 'This email appears legitimate. It comes from a trusted sender and passed strong email authentication checks.',
            'severity' => 'low',
            'matched' => [],
            'legit' => $legitFindings,
            'score' => 0,
        ];
    }

    $score = 0;
    foreach ($riskFindings as $f) {
        $score += match ($f['severity']) {
            'high' => 3,
            'medium' => 2,
            default => 1,
        };
    }

    if (!$results['auth_failed'] && $results['auth_passes'] >= 2) {
        $score = max(0, $score - 2);
    }

    if ($results['trusted_sender']) {
        $score = max(0, $score - 2);
    }

    $signalCount = count($riskFindings);

    if ($score >= 7) {
        $severity = 'high';
        $message = 'High likelihood of phishing content detected.';
    } elseif ($score >= 4) {
        $severity = 'medium';
        $message = 'Several phishing indicators were found.';
    } elseif ($score >= 1) {
        $severity = 'low';
        $message = 'A small number of phishing indicators were found.';
    } else {
        $severity = 'low';
        $message = !empty($legitFindings)
            ? 'Legitimate sender signals were found and no strong phishing indicators were detected.'
            : 'No strong phishing indicators were found.';
    }

    return [
        'message' => $message,
        'severity' => $severity,
        'matched' => $riskFindings,
        'legit' => $legitFindings,
        'score' => $signalCount,
    ];
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $emailContent = trim($_POST['email_content'] ?? '');

    if ($emailContent === '') {
        $analysisMessage = 'Please paste email content before analyzing.';
        $analysisSeverity = 'low';
        $analysisScore = 0;
    } else {
        if (detectSuspiciousInput($emailContent)) {
            logAttackEvent(
                'suspicious_request',
                'high',
                'phishing_toolkit.php',
                [
                    'reason' => 'Suspicious payload submitted into phishing toolkit'
                ]
            );
        }

        $result = analyzePhishingContent($emailContent);

        $analysisMessage = $result['message'];
        $analysisSeverity = $result['severity'];
        $analysisDetails = $result['matched'];
        $legitimacyDetails = $result['legit'];
        $analysisScore = $result['score'];

        if ($result['severity'] === 'high') {
            logAttackEvent(
                'phishing_detected',
                'high',
                'phishing_toolkit.php',
                [
                    'score' => $result['score'],
                    'matchedSignals' => array_column($result['matched'], 'label'),
                    'preview' => mb_substr($emailContent, 0, 180)
                ]
            );
        } elseif ($result['severity'] === 'medium') {
            logAttackEvent(
                'model_detection',
                'medium',
                'phishing_toolkit.php',
                [
                    'score' => $result['score'],
                    'matchedSignals' => array_column($result['matched'], 'label'),
                    'preview' => mb_substr($emailContent, 0, 180)
                ]
            );
        }
    }
}

$riskLabel = 'Low Risk';
$riskIcon = '✓';

if ($analysisSeverity === 'medium') {
    $riskLabel = 'Medium Risk';
    $riskIcon = '!';
} elseif ($analysisSeverity === 'high') {
    $riskLabel = 'High Risk';
    $riskIcon = '!';
}

$recommendations = [];

if ($analysisSeverity === 'high') {
    $recommendations = [
        'Do not click any links or open any attachments.',
        'Do not enter passwords, MFA codes, or payment details.',
        'Verify the sender through a trusted contact method.',
        'Report the message and remove it from the inbox.'
    ];
} elseif ($analysisSeverity === 'medium') {
    $recommendations = [
        'Verify any sender claims before replying.',
        'Hover over links before opening them.',
        'Avoid sharing passwords or verification codes.',
        'Treat attachments with caution.'
    ];
} else {
    $recommendations = [
        'Continue reviewing the sender and message context.',
        'Double-check unexpected links and attachments.',
        'Look for SPF, DKIM, or DMARC pass results when headers are available.',
        'Do not share credentials unless you initiated the request.'
    ];
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Phishing Toolkit | Security Dashboard</title>
    <link rel="stylesheet" href="phishing_toolkit.css">
    <style>
        .scan-actions { gap: 10px; }
        #clearBtn {
            background: rgba(255, 255, 255, 0.04);
            border-color: rgba(255, 255, 255, 0.10);
            color: #6f8b96;
        }
        #clearBtn:hover {
            background: rgba(255, 255, 255, 0.08);
            color: #dffeff;
            box-shadow: 0 12px 22px rgba(0,0,0,0.26);
        }
    </style>
</head>
<body>
    <div class="page-wrapper">
        <aside class="sidebar">
            <h2>Dashboard</h2>

            <div class="sidebar-nav">
                <a class="nav-link" href="homepage.php">Home</a>
                <a class="nav-link" href="password_checker.php">Password Check</a>
                <a class="nav-link" href="password_generator.php">Password Gen</a>
                <a class="nav-link" href="vault.php">Vault</a>
                <a class="nav-link active" href="phishing_toolkit.php">Phishing Toolkit</a>
                <a class="nav-link" href="about.php">About Me</a>
            </div>

            <div class="sidebar-spacer"></div>

            <a class="nav-link" href="../security_settings.php">Security Settings</a>
            <a class="nav-link" href="../Login/logout.php">Logout</a>
        </aside>

        <main class="main-content">
            <div class="simple-page phishing-page">
                <section class="simple-card phishing-hero-card">
                    <div class="phishing-hero-top">
                        <div>
                            <span class="scanner-badge">Threat Analysis</span>
                            <h1>Phishing Toolkit</h1>
                            <p>Analyze suspicious emails via headers or website links for common phishing indicators.</p>
                        </div>

                        <div class="hero-risk-pill hero-risk-<?= htmlspecialchars($analysisSeverity) ?>">
                            <span class="hero-risk-pill-dot"></span>
                            <?= htmlspecialchars($riskLabel) ?>
                        </div>
                    </div>

                    <form method="POST" action="">
                        <div class="form-group">
                            <label for="email_content">Suspicious Content</label>
                            <textarea
                                id="email_content"
                                name="email_content"
                                placeholder="Paste the suspicious email headers or URL here"
                                rows="8"
                            ><?= safeText($_POST['email_content'] ?? '') ?></textarea>
                        </div>

                        <div class="scan-actions">
                            <button type="submit">Analyze</button>
                            <button type="button" id="clearBtn">Clear</button>
                        </div>
                    </form>
                </section>

                <section class="top-metrics">
                    <div class="simple-card metric-card metric-risk">
                        <div class="metric-label">Risk Level</div>
                        <div class="metric-value"><?= htmlspecialchars($riskLabel) ?></div>
                        <div class="metric-subtext">
                            <?php if ($analysisMessage !== ''): ?>
                                <?= htmlspecialchars($analysisMessage) ?>
                            <?php else: ?>
                                No scan submitted yet.
                            <?php endif; ?>
                        </div>
                    </div>

                    <div class="simple-card metric-card metric-score">
                        <div class="metric-label">Signals Matched</div>
                        <div class="metric-value"><?= (int) $analysisScore ?></div>
                        <div class="metric-subtext">Triggered phishing rule matches from your current detector.</div>
                    </div>

                    <div class="simple-card metric-card metric-action">
                        <div class="metric-label">Recommended Action</div>
                        <div class="metric-value small">
                            <?php if ($analysisSeverity === 'high'): ?>
                                Stop and report
                            <?php elseif ($analysisSeverity === 'medium'): ?>
                                Verify carefully
                            <?php else: ?>
                                Review context
                            <?php endif; ?>
                        </div>
                        <div class="metric-subtext">Use caution before clicking links, replying, or entering credentials.</div>
                    </div>
                </section>

                <section class="phishing-grid">
                    <div class="simple-card scan-status-card">
                        <div class="card-header-row">
                            <h2>Scan Status</h2>
                            <span class="status-badge status-<?= htmlspecialchars($analysisSeverity) ?>">
                                <?= htmlspecialchars($riskLabel) ?>
                            </span>
                        </div>

                        <div class="scan-status-box">
                            <div class="scan-status-circle scan-status-circle-<?= htmlspecialchars($analysisSeverity) ?>">
                                <?= htmlspecialchars($riskIcon) ?>
                            </div>

                            <div>
                                <div class="scan-status-label">
                                    <?php if ($analysisMessage !== ''): ?>
                                        <?= htmlspecialchars($riskLabel) ?>
                                    <?php else: ?>
                                        Ready to analyze
                                    <?php endif; ?>
                                </div>

                                <p>
                                    <?php if ($analysisMessage !== ''): ?>
                                        <?= htmlspecialchars($analysisMessage) ?>
                                    <?php else: ?>
                                        Submit suspicious content to inspect urgency cues, risky links, credential requests, and spoofing patterns.
                                    <?php endif; ?>
                                </p>
                            </div>
                        </div>
                    </div>

                    <div class="simple-card findings-card">
                        <div class="card-header-row">
                            <h2>Threat Indicators</h2>
                            <span class="signal-count"><?= count($analysisDetails) ?> matched</span>
                        </div>

                        <div class="indicator-list">
                            <?php if (!empty($analysisDetails)): ?>
                                <?php foreach ($analysisDetails as $finding): ?>
                                    <?php
                                        $dot = htmlspecialchars($finding['severity']);
                                        $label = htmlspecialchars(ucfirst($finding['label']));
                                        $detail = htmlspecialchars($finding['detail']);
                                    ?>
                                    <div class="indicator-row active" title="<?= $detail ?>">
                                        <span class="indicator-dot <?= $dot ?>"></span>
                                        <span><?= $label ?></span>
                                    </div>
                                <?php endforeach; ?>
                            <?php elseif (!empty($legitimacyDetails)): ?>
                                <?php foreach ($legitimacyDetails as $finding): ?>
                                    <div class="indicator-row" title="<?= htmlspecialchars($finding['detail']) ?>">
                                        <span class="indicator-dot low"></span>
                                        <span><?= htmlspecialchars(ucfirst($finding['label'])) ?></span>
                                    </div>
                                <?php endforeach; ?>
                            <?php else: ?>
                                <div class="indicator-row">
                                    <span class="indicator-dot low"></span>
                                    <span>Urgent or threatening wording</span>
                                </div>

                                <div class="indicator-row">
                                    <span class="indicator-dot medium"></span>
                                    <span>Suspicious links or domain tricks</span>
                                </div>

                                <div class="indicator-row">
                                    <span class="indicator-dot medium"></span>
                                    <span>Requests for passwords or MFA codes</span>
                                </div>

                                <div class="indicator-row">
                                    <span class="indicator-dot high"></span>
                                    <span>Spoofed sender identity patterns</span>
                                </div>
                            <?php endif; ?>
                        </div>
                    </div>
                </section>

                <section class="lower-grid">
                    <div class="simple-card result-card">
                        <div class="card-header-row">
                            <h2>Scan Result</h2>
                            <span class="status-badge status-<?= htmlspecialchars($analysisSeverity) ?>">
                                <?= htmlspecialchars($riskLabel) ?>
                            </span>
                        </div>

                        <div class="placeholder-result severity-<?= htmlspecialchars($analysisSeverity) ?>">
                            <?php if ($analysisMessage !== ''): ?>
                                <strong><?= htmlspecialchars($analysisMessage) ?></strong>

                                <?php if (!empty($analysisDetails)): ?>
                                    <div class="result-section">
                                        <strong>Detected signals:</strong>
                                        <ul>
                                            <?php foreach ($analysisDetails as $finding): ?>
                                                <li>
                                                    <strong><?= htmlspecialchars(ucfirst($finding['label'])) ?>:</strong>
                                                    <?= htmlspecialchars($finding['detail']) ?>
                                                </li>
                                            <?php endforeach; ?>
                                        </ul>
                                    </div>
                                <?php else: ?>
                                    <div class="result-section">
                                        <ul>
                                            <li>No major phishing signals matched your current rules.</li>
                                        </ul>
                                    </div>
                                <?php endif; ?>

                                <?php if (!empty($legitimacyDetails)): ?>
                                    <div class="result-section">
                                        <strong>Legitimate sender signals:</strong>
                                        <ul>
                                            <?php foreach ($legitimacyDetails as $finding): ?>
                                                <li>
                                                    <strong><?= htmlspecialchars(ucfirst($finding['label'])) ?>:</strong>
                                                    <?= htmlspecialchars($finding['detail']) ?>
                                                </li>
                                            <?php endforeach; ?>
                                        </ul>
                                    </div>
                                <?php endif; ?>
                            <?php else: ?>
                                <strong>No scan yet.</strong>
                                <ul>
                                    <li>Paste suspicious content into the box above.</li>
                                    <li>Click <strong>Analyze</strong> to run the phishing checks.</li>
                                    <li>Your results and matched signals will appear here.</li>
                                </ul>
                            <?php endif; ?>
                        </div>
                    </div>

                    <div class="simple-card recommendation-card">
                        <div class="card-header-row">
                            <h2>Recommendations</h2>
                            <span class="recommendation-label">Next steps</span>
                        </div>

                        <div class="recommendation-box">
                            <ul class="recommendation-list">
                                <?php foreach ($recommendations as $item): ?>
                                    <li><?= htmlspecialchars($item) ?></li>
                                <?php endforeach; ?>
                            </ul>
                        </div>
                    </div>
                </section>
            </div>
        </main>
    </div>
<script>
    document.getElementById('clearBtn').addEventListener('click', function () {
        document.getElementById('email_content').value = '';
        document.getElementById('email_content').focus();
    });
</script>
</body>
</html>