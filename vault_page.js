(() => {
    const csrfToken =
        document.querySelector('meta[name="csrf-token"]')?.getAttribute("content") || "";

    const pageMessage = document.getElementById("pageMessage");
    const newItemBtn = document.getElementById("newItemBtn");
    const newFolderBtn = document.getElementById("newFolderBtn");
    const refreshBtn = document.getElementById("refreshBtn");
    const clearFiltersBtn = document.getElementById("clearFiltersBtn");
    const searchInput = document.getElementById("searchInput");
    const typeFilter = document.getElementById("typeFilter");
    const typeFilterButtons = document.querySelectorAll("[data-type-filter]");
    const folderFilterButtons = document.querySelectorAll("[data-folder-filter]");
    const folderList = document.getElementById("folderList");
    const vaultList = document.getElementById("vaultList");

    const statTotalItems = document.getElementById("statTotalItems");
    const statFolderCount = document.getElementById("statFolderCount");
    const statSelectedFolder = document.getElementById("statSelectedFolder");

    const itemModal = document.getElementById("itemModal");
    const itemModalTitle = document.getElementById("itemModalTitle");
    const itemMessage = document.getElementById("itemMessage");
    const itemForm = document.getElementById("itemForm");
    const cancelItemBtn = document.getElementById("cancelItemBtn");

    const itemId = document.getElementById("itemId");
    const itemName = document.getElementById("itemName");
    const itemType = document.getElementById("itemType");
    const itemFolder = document.getElementById("itemFolder");

    const templateLogin = document.getElementById("template-login");
    const templateCard = document.getElementById("template-card");
    const templateIdentity = document.getElementById("template-identity");
    const templateNote = document.getElementById("template-note");

    const loginUsername = document.getElementById("loginUsername");
    const loginPassword = document.getElementById("loginPassword");
    const loginUrl = document.getElementById("loginUrl");
    const loginTotp = document.getElementById("loginTotp");
    const loginNotes = document.getElementById("loginNotes");

    const cardholderName = document.getElementById("cardholderName");
    const cardBrand = document.getElementById("cardBrand");
    const cardNumber = document.getElementById("cardNumber");
    const cardExpMonth = document.getElementById("cardExpMonth");
    const cardExpYear = document.getElementById("cardExpYear");
    const cardCvc = document.getElementById("cardCvc");
    const cardNotes = document.getElementById("cardNotes");

    const identityTitle = document.getElementById("identityTitle");
    const identityCompany = document.getElementById("identityCompany");
    const identityFirstName = document.getElementById("identityFirstName");
    const identityMiddleName = document.getElementById("identityMiddleName");
    const identityLastName = document.getElementById("identityLastName");
    const identityEmail = document.getElementById("identityEmail");
    const identityPhone = document.getElementById("identityPhone");
    const identityAddress1 = document.getElementById("identityAddress1");
    const identityAddress2 = document.getElementById("identityAddress2");
    const identityCity = document.getElementById("identityCity");
    const identityState = document.getElementById("identityState");
    const identityPostalCode = document.getElementById("identityPostalCode");
    const identityCountry = document.getElementById("identityCountry");
    const identityNotes = document.getElementById("identityNotes");

    const noteTitle = document.getElementById("noteTitle");
    const noteContent = document.getElementById("noteContent");

    const folderModal = document.getElementById("folderModal");
    const folderNameInput = document.getElementById("folderNameInput");
    const saveFolderBtn = document.getElementById("saveFolderBtn");
    const cancelFolderBtn = document.getElementById("cancelFolderBtn");
    const folderMessage = document.getElementById("folderMessage");

    let items = [];
    let knownFolders = [];
    let selectedType = "all";
    let selectedFolder = "__all__";
    let vaultKey = null;

    function setMessage(node, text, type = "error") {
        if (!node) return;
        node.textContent = text || "";
        node.className = `vault-inline-message ${type}`;
        if (text) node.classList.remove("hidden");
        else node.classList.add("hidden");
    }

    function clearMessage(node) {
        if (!node) return;
        node.textContent = "";
        node.className = "vault-inline-message hidden";
    }

    function escapeHtml(value) {
        return String(value ?? "")
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#39;");
    }

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

    function profileHasRequiredFields(profile) {
        return !!(
            profile &&
            profile.vault_salt &&
            profile.vault_iterations &&
            profile.vault_key_check &&
            profile.wrapped_vault_key &&
            profile.wrapped_vault_key_iv
        );
    }

    function getStoredPassword() {
        return sessionStorage.getItem("vault_login_password") || "";
    }

    async function bootstrapVaultKey() {
        const password = getStoredPassword();

        if (!password) {
            throw new Error("No vault login password found in this browser session. Log in again.");
        }

        const profileRes = await apiFetch("vault_profile.php");

        const shouldCreateFreshVault =
            !profileRes.exists ||
            !profileRes.profile ||
            !profileHasRequiredFields(profileRes.profile) ||
            profileRes.profile.vault_state === "empty" ||
            profileRes.profile.vault_state === "needs_reinit";

        if (shouldCreateFreshVault) {
            const created = await window.VaultCrypto.createVaultProfile(password);

            await apiFetch("vault_init.php", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    vault_salt: created.salt,
                    vault_iterations: created.iterations,
                    vault_key_check: created.vault_key_check,
                    wrapped_vault_key: created.wrapped_vault_key,
                    wrapped_vault_key_iv: created.wrapped_vault_key_iv
                })
            });

            vaultKey = created.vaultKey;
            setMessage(pageMessage, "Vault initialized successfully.", "success");
            return;
        }

        vaultKey = await window.VaultCrypto.unlockVaultFromProfile(password, profileRes.profile);
    }

    function showTemplate(type) {
        templateLogin.classList.add("hidden");
        templateCard.classList.add("hidden");
        templateIdentity.classList.add("hidden");
        templateNote.classList.add("hidden");

        if (type === "card") templateCard.classList.remove("hidden");
        else if (type === "identity") templateIdentity.classList.remove("hidden");
        else if (type === "note") templateNote.classList.remove("hidden");
        else templateLogin.classList.remove("hidden");
    }

    function clearTemplateFields() {
        loginUsername.value = "";
        loginPassword.value = "";
        loginUrl.value = "";
        loginTotp.value = "";
        loginNotes.value = "";

        cardholderName.value = "";
        cardBrand.value = "";
        cardNumber.value = "";
        cardExpMonth.value = "";
        cardExpYear.value = "";
        cardCvc.value = "";
        cardNotes.value = "";

        identityTitle.value = "";
        identityCompany.value = "";
        identityFirstName.value = "";
        identityMiddleName.value = "";
        identityLastName.value = "";
        identityEmail.value = "";
        identityPhone.value = "";
        identityAddress1.value = "";
        identityAddress2.value = "";
        identityCity.value = "";
        identityState.value = "";
        identityPostalCode.value = "";
        identityCountry.value = "";
        identityNotes.value = "";

        noteTitle.value = "";
        noteContent.value = "";
    }

    function buildPayloadByType(type) {
        if (type === "card") {
            return {
                cardholder_name: cardholderName.value.trim(),
                brand: cardBrand.value.trim(),
                card_number: cardNumber.value.trim(),
                exp_month: cardExpMonth.value.trim(),
                exp_year: cardExpYear.value.trim(),
                cvc: cardCvc.value.trim(),
                notes: cardNotes.value.trim()
            };
        }

        if (type === "identity") {
            return {
                title: identityTitle.value.trim(),
                company: identityCompany.value.trim(),
                first_name: identityFirstName.value.trim(),
                middle_name: identityMiddleName.value.trim(),
                last_name: identityLastName.value.trim(),
                email: identityEmail.value.trim(),
                phone: identityPhone.value.trim(),
                address1: identityAddress1.value.trim(),
                address2: identityAddress2.value.trim(),
                city: identityCity.value.trim(),
                state: identityState.value.trim(),
                postal_code: identityPostalCode.value.trim(),
                country: identityCountry.value.trim(),
                notes: identityNotes.value.trim()
            };
        }

        if (type === "note") {
            return {
                note_title: noteTitle.value.trim(),
                note_content: noteContent.value.trim()
            };
        }

        return {
            username: loginUsername.value.trim(),
            password: loginPassword.value.trim(),
            url: loginUrl.value.trim(),
            totp: loginTotp.value.trim(),
            notes: loginNotes.value.trim()
        };
    }

    function fillTemplateByType(type, payload) {
        clearTemplateFields();

        if (type === "card") {
            cardholderName.value = payload.cardholder_name || "";
            cardBrand.value = payload.brand || "";
            cardNumber.value = payload.card_number || "";
            cardExpMonth.value = payload.exp_month || "";
            cardExpYear.value = payload.exp_year || "";
            cardCvc.value = payload.cvc || "";
            cardNotes.value = payload.notes || "";
            return;
        }

        if (type === "identity") {
            identityTitle.value = payload.title || "";
            identityCompany.value = payload.company || "";
            identityFirstName.value = payload.first_name || "";
            identityMiddleName.value = payload.middle_name || "";
            identityLastName.value = payload.last_name || "";
            identityEmail.value = payload.email || "";
            identityPhone.value = payload.phone || "";
            identityAddress1.value = payload.address1 || "";
            identityAddress2.value = payload.address2 || "";
            identityCity.value = payload.city || "";
            identityState.value = payload.state || "";
            identityPostalCode.value = payload.postal_code || "";
            identityCountry.value = payload.country || "";
            identityNotes.value = payload.notes || "";
            return;
        }

        if (type === "note") {
            noteTitle.value = payload.note_title || "";
            noteContent.value = payload.note_content || "";
            return;
        }

        loginUsername.value = payload.username || "";
        loginPassword.value = payload.password || "";
        loginUrl.value = payload.url || "";
        loginTotp.value = payload.totp || "";
        loginNotes.value = payload.notes || "";
    }

    function previewForItem(item) {
        const payload = item.payload || {};
        if (item.item_type === "login") return payload.username || payload.url || "";
        if (item.item_type === "card") {
            const brand = payload.brand || "Card";
            const number = String(payload.card_number || "");
            const last4 = number ? number.slice(-4) : "----";
            return `${brand}, *${last4}`;
        }
        if (item.item_type === "identity") {
            const fullName = `${payload.first_name || ""} ${payload.last_name || ""}`.trim();
            return fullName || payload.email || payload.phone || "";
        }
        if (item.item_type === "note") return payload.note_title || payload.note_content || "";
        return "";
    }

    function subTextForItem(item) {
        const payload = item.payload || {};
        if (item.item_type === "login") return payload.url || "";
        if (item.item_type === "card") return payload.cardholder_name || "";
        if (item.item_type === "identity") return payload.email || payload.company || "";
        if (item.item_type === "note") return payload.note_title || "";
        return "";
    }

    function updateStats() {
        if (statTotalItems) statTotalItems.textContent = String(items.length);
        if (statFolderCount) statFolderCount.textContent = String(knownFolders.length);
        if (statSelectedFolder) statSelectedFolder.textContent = selectedFolder === "__all__" ? "All" : selectedFolder;
    }

    function updateKnownFolders() {
        const folderSet = new Set();

        items.forEach((item) => {
            const folder = (item.folder_name || "").trim();
            if (folder) folderSet.add(folder);
        });

        knownFolders = Array.from(folderSet).sort((a, b) => a.localeCompare(b));

        if (selectedFolder !== "__all__" && !knownFolders.includes(selectedFolder)) {
            selectedFolder = "__all__";
        }

        renderFolders();
        updateFolderOptions();
        updateStats();
    }

    function updateFolderOptions() {
        const folderOptions = document.getElementById("vaultFolderOptions");
        if (!folderOptions) return;

        folderOptions.innerHTML = "";
        knownFolders.forEach((folder) => {
            const option = document.createElement("option");
            option.value = folder;
            folderOptions.appendChild(option);
        });
    }

    function renderFolders() {
        if (!folderList) return;

        if (knownFolders.length === 0) {
            folderList.innerHTML = `<div class="vault-folder-empty">No folders yet</div>`;
            return;
        }

        folderList.innerHTML = "";

        knownFolders.forEach((folder) => {
            const row = document.createElement("div");
            row.style.display = "flex";
            row.style.gap = "8px";
            row.style.alignItems = "center";
            row.style.marginBottom = "8px";

            const selectBtn = document.createElement("button");
            selectBtn.type = "button";
            selectBtn.className = "vault-folder-btn";
            selectBtn.textContent = folder;
            selectBtn.style.flex = "1";

            if (selectedFolder === folder) {
                selectBtn.classList.add("active");
            }

            selectBtn.addEventListener("click", () => {
                selectedFolder = folder;
                updateFolderFilterButtons();
                renderFolders();
                updateStats();
                renderItems();
            });

            const deleteBtn = document.createElement("button");
            deleteBtn.type = "button";
            deleteBtn.className = "vault-action-btn danger";
            deleteBtn.textContent = "Delete";

            deleteBtn.addEventListener("click", async (event) => {
                event.stopPropagation();
                await deleteFolder(folder);
            });

            row.appendChild(selectBtn);
            row.appendChild(deleteBtn);
            folderList.appendChild(row);
        });
    }

    function updateTypeFilterButtons() {
        typeFilterButtons.forEach((btn) => {
            btn.classList.toggle("active", btn.dataset.typeFilter === selectedType);
        });
    }

    function updateFolderFilterButtons() {
        folderFilterButtons.forEach((btn) => {
            btn.classList.toggle("active", btn.dataset.folderFilter === selectedFolder);
        });
    }

    function filteredItems() {
        const query = (searchInput.value || "").trim().toLowerCase();

        return items.filter((item) => {
            const payload = item.payload || {};
            const folder = (item.folder_name || "").trim();

            const matchesType = selectedType === "all" || item.item_type === selectedType;
            const matchesFolder = selectedFolder === "__all__" || folder === selectedFolder;

            const haystack = [
                item.item_name,
                item.item_type,
                folder,
                payload.username,
                payload.url,
                payload.note_title,
                payload.note_content,
                payload.brand,
                payload.cardholder_name,
                payload.first_name,
                payload.last_name,
                payload.email,
                payload.phone,
                payload.company
            ].join(" ").toLowerCase();

            return matchesType && matchesFolder && (query === "" || haystack.includes(query));
        });
    }

    function renderItems() {
        const list = filteredItems();

        if (!vaultList) return;

        if (!list.length) {
            vaultList.innerHTML = `<div class="vault-empty">No vault items found.</div>`;
            return;
        }

        vaultList.innerHTML = "";

        list.forEach((item) => {
            const row = document.createElement("div");
            row.className = "vault-row";

            const folder = (item.folder_name || "").trim();
            const folderMarkup = folder
                ? `<span class="vault-folder-pill">${escapeHtml(folder)}</span>`
                : `<span class="vault-folder-pill none">-</span>`;

            row.innerHTML = `
                <div>
                    <div class="vault-row-title">${escapeHtml(item.item_name)}</div>
                    ${subTextForItem(item) ? `<div class="vault-row-sub">${escapeHtml(subTextForItem(item))}</div>` : ""}
                </div>
                <div>
                    <span class="vault-type-pill">${escapeHtml(item.item_type)}</span>
                </div>
                <div>${folderMarkup}</div>
                <div class="vault-row-sub">${escapeHtml(previewForItem(item) || "-")}</div>
                <div class="vault-actions-dropdown">
                    <button type="button" class="vault-action-btn" data-copy="${item.id}">Copy</button>
                    <button type="button" class="vault-action-btn" data-edit="${item.id}">Edit</button>
                    <button type="button" class="vault-action-btn danger" data-delete="${item.id}">Delete</button>
                </div>
            `;

            vaultList.appendChild(row);
        });
    }

    async function loadItems() {
        clearMessage(pageMessage);

        if (!vaultKey) {
            throw new Error("Vault is locked.");
        }

        const data = await apiFetch("vault_list.php");
        const decrypted = [];

        for (const row of (data.items || [])) {
            try {
                const plain = await window.VaultCrypto.decryptText(vaultKey, row.iv, row.encrypted_data);
                const fullItem = JSON.parse(plain);

                decrypted.push({
                    id: row.id,
                    item_name: row.id && row.item_name ? row.item_name : (fullItem.item_name || "Encrypted Item"),
                    item_type: row.item_type || fullItem.item_type || "login",
                    folder_name: row.folder_name || fullItem.folder_name || "",
                    payload: fullItem.payload || {}
                });
            } catch (error) {
                console.error("Vault item decrypt failed:", error);
            }
        }

        items = decrypted;
        updateKnownFolders();
        renderItems();
    }

    async function saveEncryptedItem(fullItem, existingId = 0) {
        const encrypted = await window.VaultCrypto.encryptText(
            vaultKey,
            JSON.stringify(fullItem)
        );

        if (!encrypted || !encrypted.encrypted_data || !encrypted.iv) {
            throw new Error("Encryption failed before save.");
        }

        await apiFetch("vault_save.php", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                item_id: existingId ? Number(existingId) : 0,
                item_name: fullItem.item_name,
                item_type: fullItem.item_type,
                folder_name: fullItem.folder_name,
                encrypted_data: encrypted.encrypted_data,
                iv: encrypted.iv
            })
        });
    }

    async function deleteFolder(folderName) {
        if (!vaultKey) {
            setMessage(pageMessage, "Vault is locked.", "error");
            return;
        }

        const matchingItems = items.filter(
            (item) => (item.folder_name || "").trim() === folderName
        );

        const confirmed = window.confirm(
            `Delete folder "${folderName}"? Items will be kept, but removed from this folder.`
        );

        if (!confirmed) {
            return;
        }

        try {
            for (const item of matchingItems) {
                const updatedItem = {
                    item_name: item.item_name,
                    item_type: item.item_type,
                    folder_name: "",
                    payload: item.payload || {}
                };

                await saveEncryptedItem(updatedItem, item.id);
            }

            if (selectedFolder === folderName) {
                selectedFolder = "__all__";
            }

            setMessage(pageMessage, `Folder "${folderName}" deleted.`, "success");
            await loadItems();
        } catch (error) {
            console.error("folder delete error:", error);
            setMessage(pageMessage, error.message || "Could not delete folder.", "error");
        }
    }

    function openItemModal(existing = null) {
        clearMessage(itemMessage);
        itemForm.reset();
        itemId.value = "";
        clearTemplateFields();

        if (existing) {
            itemModalTitle.textContent = "Edit Item";
            itemId.value = existing.id;
            itemName.value = existing.item_name || "";
            itemType.value = existing.item_type || "login";
            itemFolder.value = existing.folder_name || "";
            showTemplate(itemType.value);
            fillTemplateByType(itemType.value, existing.payload || {});
        } else {
            itemModalTitle.textContent = "New Item";
            itemName.value = "";
            itemType.value = "login";
            itemFolder.value = selectedFolder !== "__all__" ? selectedFolder : "";
            showTemplate("login");
        }

        itemModal.classList.remove("hidden");
    }

    function closeItemModal() {
        itemModal.classList.add("hidden");
        clearMessage(itemMessage);
        itemForm.reset();
        clearTemplateFields();
    }

    itemType.addEventListener("change", () => {
        showTemplate(itemType.value);
    });

    itemForm.addEventListener("submit", async (event) => {
        event.preventDefault();
        clearMessage(itemMessage);

        try {
            if (!vaultKey) {
                throw new Error("Vault is locked.");
            }

            const fullItem = {
                item_name: itemName.value.trim(),
                item_type: itemType.value,
                folder_name: itemFolder.value.trim(),
                payload: buildPayloadByType(itemType.value)
            };

            if (!fullItem.item_name) {
                throw new Error("Item name is required.");
            }

            if (!fullItem.item_type) {
                throw new Error("Item type is required.");
            }

            await saveEncryptedItem(fullItem, itemId.value ? Number(itemId.value) : 0);

            closeItemModal();
            setMessage(pageMessage, "Vault item saved successfully.", "success");
            await loadItems();
        } catch (error) {
            console.error("vault save error:", error);
            setMessage(itemMessage, error.message || "Could not save vault item.", "error");
        }
    });

    if (vaultList) {
        vaultList.addEventListener("click", async (event) => {
            const editId = event.target.getAttribute("data-edit");
            const copyId = event.target.getAttribute("data-copy");
            const deleteId = event.target.getAttribute("data-delete");

            if (editId) {
                const existing = items.find((item) => String(item.id) === String(editId));
                if (existing) openItemModal(existing);
                return;
            }

            if (copyId) {
                const existing = items.find((item) => String(item.id) === String(copyId));
                if (!existing) return;

                let copyValue = "";

                if (existing.item_type === "login") copyValue = existing.payload?.password || "";
                else if (existing.item_type === "card") copyValue = existing.payload?.card_number || "";
                else if (existing.item_type === "identity") copyValue = existing.payload?.email || "";
                else if (existing.item_type === "note") copyValue = existing.payload?.note_content || "";

                if (!copyValue) {
                    setMessage(pageMessage, "Nothing to copy for this item.", "error");
                    return;
                }

                try {
                    if (
                        navigator.clipboard &&
                        (window.isSecureContext ||
                            window.location.hostname === "localhost" ||
                            window.location.hostname === "127.0.0.1")
                    ) {
                        await navigator.clipboard.writeText(copyValue);
                    } else {
                        const temp = document.createElement("textarea");
                        temp.value = copyValue;
                        temp.setAttribute("readonly", "");
                        temp.style.position = "fixed";
                        temp.style.left = "-9999px";
                        document.body.appendChild(temp);
                        temp.focus();
                        temp.select();

                        const copied = document.execCommand("copy");
                        document.body.removeChild(temp);

                        if (!copied) {
                            throw new Error("Fallback copy failed.");
                        }
                    }

                    setMessage(pageMessage, "Copied to clipboard.", "success");
                } catch (error) {
                    setMessage(pageMessage, "Could not copy item value.", "error");
                }

                return;
            }

            if (deleteId) {
                const okToDelete = window.confirm("Delete this vault item?");
                if (!okToDelete) return;

                try {
                    await apiFetch("vault_delete.php", {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({ item_id: Number(deleteId) })
                    });

                    setMessage(pageMessage, "Vault item deleted.", "success");
                    await loadItems();
                } catch (error) {
                    setMessage(pageMessage, error.message || "Delete failed.", "error");
                }
            }
        });
    }

    function openFolderModal() {
        if (!folderModal) return;

        folderNameInput.value = "";
        clearMessage(folderMessage);

        folderModal.classList.remove("hidden");
        folderNameInput.focus();
    }

    function closeFolderModal() {
        if (!folderModal) return;

        folderModal.classList.add("hidden");
        folderNameInput.value = "";
        clearMessage(folderMessage);
    }

    if (newItemBtn) newItemBtn.addEventListener("click", () => openItemModal(null));
    if (cancelItemBtn) cancelItemBtn.addEventListener("click", closeItemModal);

    if (refreshBtn) {
        refreshBtn.addEventListener("click", () => {
            bootstrapVaultKey()
                .then(loadItems)
                .catch((error) => {
                    console.error(error);
                    setMessage(pageMessage, error.message || "Could not load vault items.", "error");
                    if (vaultList) {
                        vaultList.innerHTML = `<div class="vault-empty">Could not load vault items.</div>`;
                    }
                });
        });
    }

    if (searchInput) searchInput.addEventListener("input", renderItems);

    if (typeFilter) {
        typeFilter.addEventListener("change", () => {
            selectedType = typeFilter.value;
            updateTypeFilterButtons();
            renderItems();
        });
    }

    if (clearFiltersBtn) {
        clearFiltersBtn.addEventListener("click", () => {
            selectedType = "all";
            selectedFolder = "__all__";
            if (searchInput) searchInput.value = "";
            if (typeFilter) typeFilter.value = "all";
            updateTypeFilterButtons();
            updateFolderFilterButtons();
            renderFolders();
            updateStats();
            renderItems();
        });
    }

    typeFilterButtons.forEach((btn) => {
        btn.addEventListener("click", () => {
            selectedType = btn.dataset.typeFilter;
            if (typeFilter) typeFilter.value = selectedType;
            updateTypeFilterButtons();
            renderItems();
        });
    });

    folderFilterButtons.forEach((btn) => {
        btn.addEventListener("click", () => {
            selectedFolder = btn.dataset.folderFilter;
            updateFolderFilterButtons();
            renderFolders();
            updateStats();
            renderItems();
        });
    });

    if (newFolderBtn) {
        newFolderBtn.addEventListener("click", openFolderModal);
    }

    if (cancelFolderBtn) {
        cancelFolderBtn.addEventListener("click", closeFolderModal);
    }

    if (saveFolderBtn) {
        saveFolderBtn.addEventListener("click", () => {
            const trimmed = folderNameInput.value.trim();

            if (!trimmed) {
                setMessage(folderMessage, "Folder name is required.", "error");
                return;
            }

            if (!knownFolders.includes(trimmed)) {
                knownFolders.push(trimmed);
                knownFolders.sort((a, b) => a.localeCompare(b));
            }

            selectedFolder = trimmed;

            updateFolderFilterButtons();
            renderFolders();
            updateFolderOptions();
            updateStats();

            if (itemFolder) {
                itemFolder.value = trimmed;
            }

            closeFolderModal();
        });
    }

    updateTypeFilterButtons();
    updateFolderFilterButtons();
    showTemplate("login");

    bootstrapVaultKey()
        .then(loadItems)
        .catch((error) => {
            console.error(error);
            setMessage(pageMessage, error.message || "Could not load vault items.", "error");
            if (vaultList) {
                vaultList.innerHTML = `<div class="vault-empty">Could not load vault items.</div>`;
            }
        });
})();
