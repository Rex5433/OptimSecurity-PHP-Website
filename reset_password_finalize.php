<?php
session_start();

header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Pragma: no-cache");
header("Expires: 0");

$username = $_SESSION["password_reset_username_done"] ?? "user";
$recoveryKey = $_SESSION["password_reset_recovery_key"] ?? "";
$newPassword = $_SESSION["password_reset_new_password"] ?? "";
$vaultPresent = ($_SESSION["password_reset_vault_present"] ?? "0") === "1";

if ($username === "user" && empty($_SESSION["password_reset_username_done"])) {
    header("Location: login.php");
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
    <title>Password Reset Complete | Optimsecurity</title>
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

            <div id="statusBox" class="login-success">
                Finishing password reset...
            </div>

            <p class="bottom-link" style="margin-top: 14px; margin-bottom: 18px;">
                Please wait while your account is updated.
            </p>

            <form action="login.php" method="get">
                <button type="submit" class="login-submit">Back to Login</button>
            </form>
        </div>
    </div>

    <script src="vault_crypto.js"></script>
    <script>
        (async function () {
            const statusBox = document.getElementById("statusBox");
            const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute("content") || "";
            const recoveryKey = <?= json_encode($recoveryKey) ?>;
            const newPassword = <?= json_encode($newPassword) ?>;
            const vaultPresent = <?= $vaultPresent ? "true" : "false" ?>;

            function setStatus(text, isError = false) {
                statusBox.textContent = text;
                statusBox.className = isError ? "login-error" : "login-success";
            }

            try {
                sessionStorage.clear();
                sessionStorage.setItem("vault_login_password", newPassword);
                sessionStorage.setItem("account_recovery_key", recoveryKey);

                if (!vaultPresent) {
                    setStatus("Password reset complete.");
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

                await window.VaultCrypto.unlockVaultFromRecoveryKey(recoveryKey, profile);

                const wrappedPassword = await window.VaultCrypto.rewrapVaultFromRecoveryToPassword(
                    recoveryKey,
                    newPassword,
                    profile
                );

                const wrappedRecovery = await window.VaultCrypto.rewrapVaultKeyWithRecovery(
                    recoveryKey,
                    recoveryKey,
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

                setStatus("Password reset complete. Vault access was preserved.");
            } catch (error) {
                setStatus(
                    "Password reset complete, but the vault could not be reconnected automatically.",
                    true
                );
            }
        })();
    </script>
</body>
</html>
