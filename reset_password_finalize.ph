<?php
session_start();

if (
    !isset($_SESSION["password_reset_recovery_key"]) ||
    !isset($_SESSION["password_reset_new_password"]) ||
    !isset($_SESSION["password_reset_new_recovery_key"]) ||
    !isset($_SESSION["password_reset_username_done"])
) {
    header("Location: login.php");
    exit;
}

$username = (string) $_SESSION["password_reset_username_done"];
$newRecoveryKey = (string) $_SESSION["password_reset_new_recovery_key"];
$vaultPreserved = (($_SESSION["password_reset_vault_preserved"] ?? "0") === "1");

if (empty($_SESSION["csrf_token"])) {
    $_SESSION["csrf_token"] = bin2hex(random_bytes(32));
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Password Reset Complete | Optimsecurity</title>
    <meta name="csrf-token" content="<?= htmlspecialchars($_SESSION["csrf_token"]) ?>">
    <link rel="stylesheet" href="styles.css">
    <link rel="icon" href="/favicon.ico" type="image/x-icon">
    <link rel="icon" type="image/png" sizes="32x32" href="/favicon-32x32.png">
    <link rel="icon" type="image/png" sizes="16x16" href="/favicon-16x16.png">
    <link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png">
    <link rel="manifest" href="/site.webmanifest">
    <style>
        .recovery-key-box {
            margin-top: 16px;
            padding: 16px;
            border-radius: 14px;
            border: 1px solid rgba(39, 233, 181, 0.28);
            background: rgba(39, 233, 181, 0.08);
            color: #d9fff4;
            text-align: center;
            font-weight: 800;
            letter-spacing: 1px;
            word-break: break-word;
        }

        .recovery-note {
            margin-top: 12px;
            color: #b9d2dd;
            text-align: center;
            line-height: 1.5;
        }

        .vault-success {
            margin-top: 16px;
            padding: 14px 16px;
            border-radius: 14px;
            border: 1px solid rgba(39, 233, 181, 0.28);
            background: rgba(39, 233, 181, 0.08);
            color: #d9fff4;
            line-height: 1.5;
        }

        .vault-warning {
            margin-top: 16px;
            padding: 14px 16px;
            border-radius: 14px;
            border: 1px solid rgba(255, 170, 80, 0.35);
            background: rgba(255, 170, 80, 0.10);
            color: #ffe2bf;
            line-height: 1.5;
        }
    </style>
</head>
<body>
    <div class="login-wrapper">
        <div class="login-box">
            <h1>Password Reset Complete</h1>

            <p class="bottom-link" style="margin-bottom: 14px;">
                @<?= htmlspecialchars($username) ?>
            </p>

            <div class="login-success">
                Your password has been reset successfully.
            </div>

            <?php if ($vaultPreserved): ?>
                <div class="vault-success" id="vaultStatusBox">
                    Preserving your vault...
                </div>
            <?php else: ?>
                <div class="vault-warning">
                    No existing vault profile was found for this account.
                </div>
            <?php endif; ?>

            <div class="recovery-key-box">
                <?= htmlspecialchars($newRecoveryKey) ?>
            </div>

            <div class="recovery-note">
                This new recovery key is shown only once. Save it somewhere secure before leaving this page.
            </div>

            <div class="divider"></div>

            <p class="bottom-link">
                <a href="login.php">Back to Login</a>
            </p>
        </div>
    </div>

    <script src="vault_crypto.js?v=200"></script>
    <script>
        (async () => {
            const csrfToken =
                document.querySelector('meta[name="csrf-token"]')?.getAttribute("content") || "";
            const vaultStatusBox = document.getElementById("vaultStatusBox");

            const oldRecoveryKey = <?= json_encode($_SESSION["password_reset_recovery_key"]) ?>;
            const newPassword = <?= json_encode($_SESSION["password_reset_new_password"]) ?>;
            const newRecoveryKey = <?= json_encode($_SESSION["password_reset_new_recovery_key"]) ?>;
            const vaultPreserved = <?= json_encode($vaultPreserved) ?>;

            async function apiFetch(url, options = {}) {
                const opts = { ...options };
                opts.headers = {
                    ...(options.headers || {}),
                    "X-CSRF-Token": csrfToken
                };

                const res = await fetch(url, opts);
                const raw = await res.text();

                let data = {};
                try {
                    data = raw ? JSON.parse(raw) : {};
                } catch (error) {
                    throw new Error(`Invalid JSON from ${url}: ${raw.substring(0, 300)}`);
                }

                if (!res.ok || data.ok === false) {
                    throw new Error(data.debug || data.error || `Request failed for ${url}`);
                }

                return data;
            }

            if (!vaultPreserved) {
                return;
            }

            try {
                const profileRes = await apiFetch("vault_profile.php");
                if (!profileRes.exists || !profileRes.profile) {
                    if (vaultStatusBox) {
                        vaultStatusBox.textContent = "No vault profile found to preserve.";
                    }
                    return;
                }

                const profile = profileRes.profile;

                const passwordWrap = await window.VaultCrypto.rewrapVaultFromRecoveryToPassword(
                    oldRecoveryKey,
                    newPassword,
                    profile
                );

                const recoveryWrap = await window.VaultCrypto.rewrapVaultKeyWithRecovery(
                    oldRecoveryKey,
                    newRecoveryKey,
                    profile
                );

                await apiFetch("vault_rewrap_after_recovery.php", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json"
                    },
                    body: JSON.stringify({
                        wrapped_vault_key: passwordWrap.wrapped_vault_key,
                        wrapped_vault_key_iv: passwordWrap.wrapped_vault_key_iv,
                        wrapped_vault_key_recovery: recoveryWrap.wrapped_vault_key_recovery,
                        wrapped_vault_key_recovery_iv: recoveryWrap.wrapped_vault_key_recovery_iv
                    })
                });

                sessionStorage.setItem("vault_login_password", newPassword);

                if (vaultStatusBox) {
                    vaultStatusBox.textContent = "Your vault was preserved successfully.";
                }
            } catch (error) {
                console.error(error);
                if (vaultStatusBox) {
                    vaultStatusBox.className = "vault-warning";
                    vaultStatusBox.textContent = "Your password was reset, but the vault could not be preserved automatically.";
                }
            }
        })();
    </script>
</body>
</html>
