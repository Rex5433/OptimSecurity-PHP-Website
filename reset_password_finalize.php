<?php
session_start();

header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Pragma: no-cache");
header("Expires: 0");

if (!isset($_SESSION["user_id"])) {
    header("Location: login.php");
    exit;
}

$username = $_SESSION["password_reset_username_done"] ?? ($_SESSION["user_username"] ?? "user");
$recoveryKey = $_SESSION["password_reset_recovery_key"] ?? "";
$newPassword = $_SESSION["password_reset_new_password"] ?? "";
$newRecoveryKey = $_SESSION["password_reset_new_recovery_key"] ?? "";
$vaultPresent = ($_SESSION["password_reset_vault_present"] ?? "0") === "1";

if ($newRecoveryKey === "" || $newPassword === "" || $recoveryKey === "") {
    header("Location: security_settings.php");
    exit;
}

if (empty($_SESSION["csrf_token"])) {
    $_SESSION["csrf_token"] = bin2hex(random_bytes(32));
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Finalize Password Reset | Optimsecurity</title>
    <meta name="csrf-token" content="<?= htmlspecialchars($_SESSION["csrf_token"]) ?>">
    <link rel="stylesheet" href="styles.css">
    <link rel="icon" href="/favicon.ico" type="image/x-icon">
    <link rel="icon" type="image/png" sizes="32x32" href="/favicon-32x32.png">
    <link rel="icon" type="image/png" sizes="16x16" href="/favicon-16x16.png">
    <link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png">
    <link rel="manifest" href="/site.webmanifest">
</head>
<body>
    <div class="login-wrapper">
        <div class="login-box">
            <h1>Password Reset Complete</h1>

            <p class="bottom-link" style="margin-bottom: 14px;">
                @<?= htmlspecialchars($username) ?>
            </p>

            <div id="statusBox" class="login-error" style="display:none;"></div>

            <div class="form-group">
                <label>New Recovery Key</label>
                <input type="text" value="<?= htmlspecialchars($newRecoveryKey) ?>" readonly>
            </div>

            <p class="bottom-link" style="margin-top: 14px;">
                Save this new recovery key now. It replaces the old one.
            </p>

            <form id="continueForm" action="vault.php" method="get">
                <button type="submit" class="login-submit">Continue</button>
            </form>
        </div>
    </div>

    <script src="vault_crypto.js"></script>
    <script>
        (async function () {
            const statusBox = document.getElementById("statusBox");
            const vaultPresent = <?= $vaultPresent ? "true" : "false" ?>;
            const oldRecoveryKey = <?= json_encode($recoveryKey) ?>;
            const newPassword = <?= json_encode($newPassword) ?>;
            const newRecoveryKey = <?= json_encode($newRecoveryKey) ?>;
            const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute("content") || "";

            function showStatus(text, isError = false) {
                statusBox.style.display = "block";
                statusBox.className = isError ? "login-error" : "login-success";
                statusBox.textContent = text;
            }

            try {
                sessionStorage.setItem("vault_login_password", newPassword);
                sessionStorage.setItem("vault_recovery_key", newRecoveryKey);

                if (!vaultPresent) {
                    showStatus("Password reset complete. No vault re-wrap was needed.");
                    return;
                }

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

                const vaultKey = await window.VaultCrypto.unlockVaultFromRecoveryKey(
                    oldRecoveryKey,
                    profile
                );

                const wrappedPassword = await window.VaultCrypto.rewrapVaultFromRecoveryToPassword(
                    oldRecoveryKey,
                    newPassword,
                    profile
                );

                const wrappedRecovery = await window.VaultCrypto.rewrapVaultKeyWithRecovery(
                    oldRecoveryKey,
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
                        wrapped_vault_key_recovery_iv: wrappedRecovery.wrapped_vault_key_recovery_iv
                    })
                });

                const saveRaw = await saveRes.text();
                const saveData = saveRaw ? JSON.parse(saveRaw) : {};

                if (!saveRes.ok || !saveData.ok) {
                    throw new Error(saveData.error || saveData.debug || "Could not update vault profile.");
                }

                showStatus("Password reset complete. Vault access was preserved.");
            } catch (error) {
                showStatus(
                    "Password reset worked, but vault re-wrap failed. Try logging in and regenerating access, or retry this flow. " +
                    (error?.message ? "Details: " + error.message : ""),
                    true
                );
            }
        })();
    </script>
</body>
</html>
