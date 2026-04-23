<?php
session_start();

header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Pragma: no-cache");
header("Expires: 0");

if (!isset($_SESSION["user_id"])) {
    header("Location: login.php");
    exit;
}

if (empty($_SESSION["csrf_token"])) {
    $_SESSION["csrf_token"] = bin2hex(random_bytes(32));
}

$username = $_SESSION["user_username"] ?? "user";
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Repair Vault | Optimsecurity</title>
    <meta name="csrf-token" content="<?= htmlspecialchars($_SESSION["csrf_token"]) ?>">
    <link rel="stylesheet" href="styles.css">
    <link rel="icon" href="/favicon.ico" type="image/x-icon">
    <link rel="icon" type="image/png" sizes="32x32" href="/favicon-32x32.png">
    <link rel="icon" type="image/png" sizes="16x16" href="/favicon-16x16.png">
    <link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png">
    <link rel="manifest" href="/site.webmanifest">
    <style>
        .repair-note {
            color: #9bb3c3;
            margin-bottom: 16px;
            line-height: 1.5;
        }
        .repair-success {
            background: rgba(39, 233, 181, 0.12);
            border: 1px solid rgba(39, 233, 181, 0.35);
            color: #27e9b5;
            padding: 12px 14px;
            border-radius: 12px;
            margin-bottom: 14px;
        }
        .repair-error {
            background: rgba(255, 112, 112, 0.12);
            border: 1px solid rgba(255, 112, 112, 0.35);
            color: #ffb0b0;
            padding: 12px 14px;
            border-radius: 12px;
            margin-bottom: 14px;
        }
    </style>
</head>
<body>
    <div class="login-wrapper">
        <div class="login-box">
            <h1>Repair Vault</h1>

            <p class="bottom-link" style="margin-bottom: 14px;">
                @<?= htmlspecialchars($username) ?>
            </p>

            <p class="repair-note">
                Use this to repair your existing vault without deleting items.
                You need the original vault recovery key that the vault was using before the reset problem happened.
            </p>

            <div id="statusBox" style="display:none;"></div>

            <form id="repairForm">
                <div class="form-group">
                    <label for="old_vault_recovery_key">Original Vault Recovery Key</label>
                    <input
                        type="text"
                        id="old_vault_recovery_key"
                        placeholder="Enter the original vault recovery key"
                        required
                    >
                </div>

                <div class="form-group">
                    <label for="current_password">Current Login Password</label>
                    <input
                        type="password"
                        id="current_password"
                        placeholder="Enter your current login password"
                        required
                    >
                </div>

                <div class="form-group">
                    <label for="new_recovery_key">Recovery Key To Use Going Forward</label>
                    <input
                        type="text"
                        id="new_recovery_key"
                        placeholder="Enter the recovery key you want the vault to use now"
                        required
                    >
                </div>

                <button type="submit" class="login-submit">Repair Vault</button>
            </form>

            <div class="divider"></div>

            <p class="bottom-link">
                <a href="security_settings.php">Back to Security Settings</a>
            </p>
        </div>
    </div>

    <script src="vault_crypto.js"></script>
    <script>
        const form = document.getElementById("repairForm");
        const statusBox = document.getElementById("statusBox");
        const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute("content") || "";

        function showStatus(text, isError = false) {
            statusBox.style.display = "block";
            statusBox.className = isError ? "repair-error" : "repair-success";
            statusBox.textContent = text;
        }

        form.addEventListener("submit", async (event) => {
            event.preventDefault();
            statusBox.style.display = "none";

            const oldVaultRecoveryKey = document.getElementById("old_vault_recovery_key").value.trim();
            const currentPassword = document.getElementById("current_password").value.trim();
            const newRecoveryKey = document.getElementById("new_recovery_key").value.trim();

            if (!oldVaultRecoveryKey || !currentPassword || !newRecoveryKey) {
                showStatus("Fill in all fields.", true);
                return;
            }

            try {
                const profileRes = await fetch("vault_profile.php", {
                    headers: {
                        "X-Requested-With": "XMLHttpRequest"
                    }
                });

                const profileRaw = await profileRes.text();
                const profileData = profileRaw ? JSON.parse(profileRaw) : {};

                if (!profileData.ok || !profileData.exists || !profileData.profile) {
                    throw new Error("Could not load vault profile.");
                }

                const profile = profileData.profile;

                await window.VaultCrypto.unlockVaultFromRecoveryKey(
                    oldVaultRecoveryKey,
                    profile
                );

                const wrappedPassword = await window.VaultCrypto.rewrapVaultFromRecoveryToPassword(
                    oldVaultRecoveryKey,
                    currentPassword,
                    profile
                );

                const wrappedRecovery = await window.VaultCrypto.rewrapVaultKeyWithRecovery(
                    oldVaultRecoveryKey,
                    newRecoveryKey,
                    profile
                );

                const saveRes = await fetch("vault_init.php", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        "X-CSRF-Token": csrfToken
                    },
                    body: JSON.stringify({
                        vault_salt: profile.vault_salt,
                        vault_iterations: profile.vault_iterations,
                        vault_key_check: profile.vault_key_check,
                        wrapped_vault_key: wrappedPassword.wrapped_vault_key,
                        wrapped_vault_key_iv: wrappedPassword.wrapped_vault_key_iv,
                        wrapped_vault_key_recovery: wrappedRecovery.wrapped_vault_key_recovery,
                        wrapped_vault_key_recovery_iv: wrappedRecovery.wrapped_vault_key_recovery_iv,
                        plain_recovery_key: newRecoveryKey
                    })
                });

                const saveRaw = await saveRes.text();
                const saveData = saveRaw ? JSON.parse(saveRaw) : {};

                if (!saveRes.ok || !saveData.ok) {
                    throw new Error(saveData.error || saveData.debug || "Could not save repaired vault profile.");
                }

                sessionStorage.setItem("vault_login_password", currentPassword);
                sessionStorage.setItem("vault_recovery_key", newRecoveryKey);

                showStatus("Vault repaired successfully. Redirecting...");
                setTimeout(() => {
                    window.location.href = "vault.php";
                }, 1200);
            } catch (error) {
                showStatus(
                    "Vault repair failed. Make sure the original vault recovery key is correct. " +
                    (error?.message ? "Details: " + error.message : ""),
                    true
                );
            }
        });
    </script>
</body>
</html>
