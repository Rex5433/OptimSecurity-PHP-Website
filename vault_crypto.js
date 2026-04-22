window.VaultCrypto = (() => {
    const encoder = new TextEncoder();
    const decoder = new TextDecoder();

    function isLocalhost() {
        const host = window.location.hostname || "";
        return host === "localhost" || host === "::1" || host === "127.0.0.1";
    }

    function getCryptoObject() {
        return window.crypto || self.crypto || null;
    }

    function getSubtleCrypto() {
        const cryptoObj = getCryptoObject();
        if (!cryptoObj) return null;
        return cryptoObj.subtle || cryptoObj.webkitSubtle || null;
    }

    function ensureCrypto() {
        const protocol = window.location.protocol || "";
        const host = window.location.hostname || "";
        const cryptoObj = getCryptoObject();
        const subtle = getSubtleCrypto();

        const allowedContext =
            window.isSecureContext ||
            (protocol === "http:" && isLocalhost());

        if (!allowedContext) {
            throw new Error(
                "Vault encryption requires HTTPS in production. For local development, use http://localhost/..."
            );
        }

        if (!cryptoObj || !subtle) {
            throw new Error(
                "Browser crypto API is unavailable in this context. Use a current browser and open the vault from http://localhost/... locally, or HTTPS in production."
            );
        }

        return { cryptoObj, subtle };
    }

    function arrayBufferToBase64(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = "";
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    }

    function base64ToArrayBuffer(base64) {
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes.buffer;
    }

    function randomBytes(length) {
        const { cryptoObj } = ensureCrypto();
        return cryptoObj.getRandomValues(new Uint8Array(length));
    }

    function randomBytesBase64(length = 16) {
        return arrayBufferToBase64(randomBytes(length).buffer);
    }

    async function deriveWrappingKey(secret, saltBase64, iterations = 210000) {
        const { subtle } = ensureCrypto();

        const baseKey = await subtle.importKey(
            "raw",
            encoder.encode(secret),
            { name: "PBKDF2" },
            false,
            ["deriveKey"]
        );

        return subtle.deriveKey(
            {
                name: "PBKDF2",
                salt: new Uint8Array(base64ToArrayBuffer(saltBase64)),
                iterations,
                hash: "SHA-256"
            },
            baseKey,
            {
                name: "AES-GCM",
                length: 256
            },
            false,
            ["encrypt", "decrypt"]
        );
    }

    async function generateVaultKey() {
        const { subtle } = ensureCrypto();
        return subtle.generateKey(
            {
                name: "AES-GCM",
                length: 256
            },
            true,
            ["encrypt", "decrypt"]
        );
    }

    async function exportVaultKeyRaw(vaultKey) {
        const { subtle } = ensureCrypto();
        return subtle.exportKey("raw", vaultKey);
    }

    async function importVaultKeyRaw(rawBuffer) {
        const { subtle } = ensureCrypto();
        return subtle.importKey(
            "raw",
            rawBuffer,
            { name: "AES-GCM" },
            true,
            ["encrypt", "decrypt"]
        );
    }

    async function encryptText(key, plainText) {
        const { subtle } = ensureCrypto();
        const ivBytes = randomBytes(12);

        const encrypted = await subtle.encrypt(
            { name: "AES-GCM", iv: ivBytes },
            key,
            encoder.encode(plainText)
        );

        return {
            iv: arrayBufferToBase64(ivBytes.buffer),
            encrypted_data: arrayBufferToBase64(encrypted)
        };
    }

    async function decryptText(key, ivBase64, cipherBase64) {
        const { subtle } = ensureCrypto();

        const decrypted = await subtle.decrypt(
            {
                name: "AES-GCM",
                iv: new Uint8Array(base64ToArrayBuffer(ivBase64))
            },
            key,
            base64ToArrayBuffer(cipherBase64)
        );

        return decoder.decode(decrypted);
    }

    async function wrapVaultKeyWithSecret(secret, vaultKey, saltBase64, iterations = 210000) {
        const wrappingKey = await deriveWrappingKey(secret, saltBase64, iterations);
        const rawVaultKey = await exportVaultKeyRaw(vaultKey);
        const ivBytes = randomBytes(12);
        const { subtle } = ensureCrypto();

        const wrapped = await subtle.encrypt(
            { name: "AES-GCM", iv: ivBytes },
            wrappingKey,
            rawVaultKey
        );

        return {
            wrapped_vault_key: arrayBufferToBase64(wrapped),
            wrapped_vault_key_iv: arrayBufferToBase64(ivBytes.buffer)
        };
    }

    async function unwrapVaultKeyWithSecret(secret, wrappedVaultKeyBase64, wrappedVaultKeyIvBase64, saltBase64, iterations = 210000) {
        const wrappingKey = await deriveWrappingKey(secret, saltBase64, iterations);
        const { subtle } = ensureCrypto();

        const rawVaultKey = await subtle.decrypt(
            {
                name: "AES-GCM",
                iv: new Uint8Array(base64ToArrayBuffer(wrappedVaultKeyIvBase64))
            },
            wrappingKey,
            base64ToArrayBuffer(wrappedVaultKeyBase64)
        );

        return importVaultKeyRaw(rawVaultKey);
    }

    async function createVaultProfile(password, recoveryKey, iterations = 210000) {
        const salt = randomBytesBase64(16);
        const vaultKey = await generateVaultKey();

        const wrappedPassword = await wrapVaultKeyWithSecret(password, vaultKey, salt, iterations);
        const wrappedRecovery = await wrapVaultKeyWithSecret(recoveryKey, vaultKey, salt, iterations);
        const check = await encryptText(vaultKey, "vault-check");

        return {
            salt,
            iterations,
            wrapped_vault_key: wrappedPassword.wrapped_vault_key,
            wrapped_vault_key_iv: wrappedPassword.wrapped_vault_key_iv,
            wrapped_vault_key_recovery: wrappedRecovery.wrapped_vault_key,
            wrapped_vault_key_recovery_iv: wrappedRecovery.wrapped_vault_key_iv,
            vault_key_check: JSON.stringify(check),
            vaultKey
        };
    }

    async function assertVaultCheck(vaultKey, profile) {
        const checkPayload = JSON.parse(profile.vault_key_check);
        const plain = await decryptText(vaultKey, checkPayload.iv, checkPayload.encrypted_data);

        if (plain !== "vault-check") {
            throw new Error("Vault key check failed.");
        }
    }

    async function unlockVaultFromProfile(password, profile) {
        const vaultKey = await unwrapVaultKeyWithSecret(
            password,
            profile.wrapped_vault_key,
            profile.wrapped_vault_key_iv,
            profile.vault_salt,
            Number(profile.vault_iterations)
        );

        await assertVaultCheck(vaultKey, profile);
        return vaultKey;
    }

    async function unlockVaultFromRecoveryKey(recoveryKey, profile) {
        const vaultKey = await unwrapVaultKeyWithSecret(
            recoveryKey,
            profile.wrapped_vault_key_recovery,
            profile.wrapped_vault_key_recovery_iv,
            profile.vault_salt,
            Number(profile.vault_iterations)
        );

        await assertVaultCheck(vaultKey, profile);
        return vaultKey;
    }

    async function rewrapVaultKey(oldPassword, newPassword, profile) {
        const vaultKey = await unlockVaultFromProfile(oldPassword, profile);

        const wrapped = await wrapVaultKeyWithSecret(
            newPassword,
            vaultKey,
            profile.vault_salt,
            Number(profile.vault_iterations)
        );

        return {
            wrapped_vault_key: wrapped.wrapped_vault_key,
            wrapped_vault_key_iv: wrapped.wrapped_vault_key_iv
        };
    }

    async function rewrapVaultKeyWithRecovery(oldRecoveryKey, newRecoveryKey, profile) {
        const vaultKey = await unlockVaultFromRecoveryKey(oldRecoveryKey, profile);

        const wrapped = await wrapVaultKeyWithSecret(
            newRecoveryKey,
            vaultKey,
            profile.vault_salt,
            Number(profile.vault_iterations)
        );

        return {
            wrapped_vault_key_recovery: wrapped.wrapped_vault_key,
            wrapped_vault_key_recovery_iv: wrapped.wrapped_vault_key_iv
        };
    }

    async function rewrapVaultFromRecoveryToPassword(recoveryKey, newPassword, profile) {
        const vaultKey = await unlockVaultFromRecoveryKey(recoveryKey, profile);

        const wrappedPassword = await wrapVaultKeyWithSecret(
            newPassword,
            vaultKey,
            profile.vault_salt,
            Number(profile.vault_iterations)
        );

        return {
            wrapped_vault_key: wrappedPassword.wrapped_vault_key,
            wrapped_vault_key_iv: wrappedPassword.wrapped_vault_key_iv
        };
    }

    return {
        createVaultProfile,
        unlockVaultFromProfile,
        unlockVaultFromRecoveryKey,
        encryptText,
        decryptText,
        rewrapVaultKey,
        rewrapVaultKeyWithRecovery,
        rewrapVaultFromRecoveryToPassword
    };
})();
