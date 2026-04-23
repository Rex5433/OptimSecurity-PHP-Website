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

$name = $_SESSION["user_name"] ?? "User";
$username = $_SESSION["user_username"] ?? "user";
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vault | Optimsecurity</title>
    <meta name="csrf-token" content="<?= htmlspecialchars($_SESSION["csrf_token"]) ?>">
    <link rel="stylesheet" href="vault.css?v=52">
    <link rel="icon" href="/favicon.ico" type="image/x-icon">

    <link rel="icon" type="image/png" sizes="32x32" href="/favicon-32x32.png">
    <link rel="icon" type="image/png" sizes="16x16" href="/favicon-16x16.png">

    <link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png">
    <link rel="manifest" href="/site.webmanifest">
</head>
<body class="vault-body">
    <div class="vault-shell">
        <aside class="vault-sidebar">
            <div class="vault-sidebar-title">Dashboard</div>

            <nav class="vault-nav">
                <a class="vault-nav-item" href="homepage.php">Home</a>
                <a class="vault-nav-item" href="password_checker.php">Password Check</a>
                <a class="vault-nav-item" href="password_generator.php">Password Gen</a>
                <a class="vault-nav-item active" href="vault.php">Vault</a>
                <a class="vault-nav-item" href="phishing_toolkit.php">Phishing Toolkit</a>
                <a class="vault-nav-item" href="about.php">About Me</a>

                <div class="vault-sidebar-spacer"></div>

                <a class="vault-nav-item" href="security_settings.php">Security Settings</a>
                <a class="vault-nav-item logout" href="logout.php">Logout</a>
            </nav>
        </aside>

        <main class="vault-main">
            <section class="vault-topbar">
                <div>
                    <div class="vault-badge">Vault</div>
                    <h1>All Vault Items</h1>
                    <p>Welcome back, <?= htmlspecialchars($name) ?>.</p>
                </div>

                <div class="vault-topbar-right">
                    <div class="vault-user-chip">@<?= htmlspecialchars($username) ?></div>
                    <button type="button" class="vault-secondary-btn" id="newFolderBtn">+ Folder</button>
                    <button type="button" class="vault-primary-btn" id="newItemBtn">+ New</button>
                </div>
            </section>

            <section class="vault-stats-row">
                <div class="vault-stat-card">
                    <span class="vault-stat-label">Total Items</span>
                    <span class="vault-stat-value" id="statTotalItems">0</span>
                </div>

                <div class="vault-stat-card">
                    <span class="vault-stat-label">Folders</span>
                    <span class="vault-stat-value" id="statFolderCount">0</span>
                </div>

                <div class="vault-stat-card">
                    <span class="vault-stat-label">Selected Folder</span>
                    <span class="vault-stat-value" id="statSelectedFolder">All</span>
                </div>
            </section>

            <section class="vault-workspace">
                <aside class="vault-left-panel">
                    <div class="vault-panel-card">
                        <div class="vault-panel-title">Filters</div>

                        <div class="vault-search-wrap">
                            <input type="text" id="searchInput" placeholder="Search vault items...">
                        </div>

                        <div class="vault-filter-block">
                            <div class="vault-filter-heading">Types</div>
                            <button type="button" class="vault-filter-btn active" data-type-filter="all">All Types</button>
                            <button type="button" class="vault-filter-btn" data-type-filter="login">Login</button>
                            <button type="button" class="vault-filter-btn" data-type-filter="card">Card</button>
                            <button type="button" class="vault-filter-btn" data-type-filter="identity">Identity</button>
                            <button type="button" class="vault-filter-btn" data-type-filter="note">Secure Note</button>
                        </div>

                        <div class="vault-filter-block">
                            <div class="vault-filter-heading">Folders</div>

                            <button type="button" class="vault-folder-btn active" data-folder-filter="__all__">
                                All Folders
                            </button>

                            <div id="folderList" class="vault-folder-list">
                                <div class="vault-folder-empty">No folders yet</div>
                            </div>
                        </div>
                    </div>
                </aside>

                <section class="vault-right-panel">
                    <div class="vault-toolbar">
                        <div class="vault-filter-wrap">
                            <select id="typeFilter">
                                <option value="all">All Types</option>
                                <option value="login">Login</option>
                                <option value="card">Card</option>
                                <option value="identity">Identity</option>
                                <option value="note">Secure Note</option>
                            </select>
                        </div>

                        <button type="button" class="vault-secondary-btn" id="clearFiltersBtn">Clear Filters</button>
                        <button type="button" class="vault-secondary-btn" id="refreshBtn">Refresh</button>
                    </div>

                    <div class="vault-content-card">
                        <div id="pageMessage" class="vault-inline-message hidden"></div>

                        <div class="vault-table-head">
                            <div>Name</div>
                            <div>Type</div>
                            <div>Folder</div>
                            <div>Preview</div>
                            <div>Actions</div>
                        </div>

                        <div id="vaultList" class="vault-list">
                            <div class="vault-empty">Loading vault items...</div>
                        </div>
                    </div>
                </section>
            </section>
        </main>
    </div>

    <div class="vault-modal-backdrop hidden" id="itemModal">
        <div class="vault-modal wide">
            <div class="vault-modal-badge">Vault Item</div>
            <h2 id="itemModalTitle">New Item</h2>

            <div id="itemMessage" class="vault-inline-message hidden"></div>

            <form id="itemForm">
                <input type="hidden" id="itemId">

                <div class="vault-grid vault-grid-top">
                    <div class="vault-form-group">
                        <label for="itemName">Item Name</label>
                        <input type="text" id="itemName" required>
                    </div>

                    <div class="vault-form-group">
                        <label for="itemType">Item Type</label>
                        <select id="itemType" required>
                            <option value="login">Login</option>
                            <option value="card">Card</option>
                            <option value="identity">Identity</option>
                            <option value="note">Secure Note</option>
                        </select>
                    </div>

                    <div class="vault-form-group">
                        <label for="itemFolder">Folder</label>
                        <input type="text" id="itemFolder" placeholder="Optional folder name" list="vaultFolderOptions">
                        <datalist id="vaultFolderOptions"></datalist>
                    </div>
                </div>

                <div id="template-login" class="vault-template">
                    <div class="vault-grid">
                        <div class="vault-form-group">
                            <label for="loginUsername">Username / Email</label>
                            <input type="text" id="loginUsername">
                        </div>

                        <div class="vault-form-group">
                            <label for="loginPassword">Password</label>
                            <input type="text" id="loginPassword">
                        </div>
                    </div>

                    <div class="vault-grid">
                        <div class="vault-form-group">
                            <label for="loginUrl">Website / URL</label>
                            <input type="text" id="loginUrl">
                        </div>

                        <div class="vault-form-group">
                            <label for="loginTotp">TOTP / MFA Secret</label>
                            <input type="text" id="loginTotp">
                        </div>
                    </div>

                    <div class="vault-form-group">
                        <label for="loginNotes">Notes</label>
                        <textarea id="loginNotes" rows="5"></textarea>
                    </div>
                </div>

                <div id="template-card" class="vault-template hidden">
                    <div class="vault-grid">
                        <div class="vault-form-group">
                            <label for="cardholderName">Cardholder Name</label>
                            <input type="text" id="cardholderName">
                        </div>

                        <div class="vault-form-group">
                            <label for="cardBrand">Brand</label>
                            <input type="text" id="cardBrand">
                        </div>
                    </div>

                    <div class="vault-grid">
                        <div class="vault-form-group">
                            <label for="cardNumber">Card Number</label>
                            <input type="text" id="cardNumber">
                        </div>

                        <div class="vault-form-group">
                            <label for="cardCvc">CVC</label>
                            <input type="text" id="cardCvc">
                        </div>
                    </div>

                    <div class="vault-grid">
                        <div class="vault-form-group">
                            <label for="cardExpMonth">Expiration Month</label>
                            <input type="text" id="cardExpMonth" placeholder="MM">
                        </div>

                        <div class="vault-form-group">
                            <label for="cardExpYear">Expiration Year</label>
                            <input type="text" id="cardExpYear" placeholder="YYYY">
                        </div>
                    </div>

                    <div class="vault-form-group">
                        <label for="cardNotes">Notes</label>
                        <textarea id="cardNotes" rows="5"></textarea>
                    </div>
                </div>

                <div id="template-identity" class="vault-template hidden">
                    <div class="vault-grid">
                        <div class="vault-form-group">
                            <label for="identityTitle">Title</label>
                            <input type="text" id="identityTitle">
                        </div>

                        <div class="vault-form-group">
                            <label for="identityCompany">Company</label>
                            <input type="text" id="identityCompany">
                        </div>
                    </div>

                    <div class="vault-grid identity-grid-3">
                        <div class="vault-form-group">
                            <label for="identityFirstName">First Name</label>
                            <input type="text" id="identityFirstName">
                        </div>

                        <div class="vault-form-group">
                            <label for="identityMiddleName">Middle Name</label>
                            <input type="text" id="identityMiddleName">
                        </div>

                        <div class="vault-form-group">
                            <label for="identityLastName">Last Name</label>
                            <input type="text" id="identityLastName">
                        </div>
                    </div>

                    <div class="vault-grid">
                        <div class="vault-form-group">
                            <label for="identityEmail">Email</label>
                            <input type="text" id="identityEmail">
                        </div>

                        <div class="vault-form-group">
                            <label for="identityPhone">Phone</label>
                            <input type="text" id="identityPhone">
                        </div>
                    </div>

                    <div class="vault-grid">
                        <div class="vault-form-group">
                            <label for="identityAddress1">Address 1</label>
                            <input type="text" id="identityAddress1">
                        </div>

                        <div class="vault-form-group">
                            <label for="identityAddress2">Address 2</label>
                            <input type="text" id="identityAddress2">
                        </div>
                    </div>

                    <div class="vault-grid identity-grid-4">
                        <div class="vault-form-group">
                            <label for="identityCity">City</label>
                            <input type="text" id="identityCity">
                        </div>

                        <div class="vault-form-group">
                            <label for="identityState">State</label>
                            <input type="text" id="identityState">
                        </div>

                        <div class="vault-form-group">
                            <label for="identityPostalCode">Postal Code</label>
                            <input type="text" id="identityPostalCode">
                        </div>

                        <div class="vault-form-group">
                            <label for="identityCountry">Country</label>
                            <input type="text" id="identityCountry">
                        </div>
                    </div>

                    <div class="vault-form-group">
                        <label for="identityNotes">Notes</label>
                        <textarea id="identityNotes" rows="5"></textarea>
                    </div>
                </div>

                <div id="template-note" class="vault-template hidden">
                    <div class="vault-form-group">
                        <label for="noteTitle">Note Title</label>
                        <input type="text" id="noteTitle">
                    </div>

                    <div class="vault-form-group">
                        <label for="noteContent">Secure Note</label>
                        <textarea id="noteContent" rows="10"></textarea>
                    </div>
                </div>

                <div class="vault-actions-row">
                    <button type="button" class="vault-secondary-btn" id="cancelItemBtn">Cancel</button>
                    <button type="submit" class="vault-primary-btn">Save Item</button>
                </div>
            </form>
        </div>
    </div>

    <div class="vault-modal-backdrop hidden" id="folderModal">
        <div class="vault-modal" style="max-width: 500px;">
            <div class="vault-modal-badge">Folder</div>
            <h2>Create Folder</h2>

            <div id="folderMessage" class="vault-inline-message hidden"></div>

            <div class="vault-form-group">
                <label for="folderNameInput">Folder Name</label>
                <input type="text" id="folderNameInput" placeholder="Enter folder name">
            </div>

            <div class="vault-actions-row">
                <button type="button" class="vault-secondary-btn" id="cancelFolderBtn">
                    Cancel
                </button>

                <button type="button" class="vault-primary-btn" id="saveFolderBtn">
                    Create Folder
                </button>
            </div>
        </div>
    </div>

    <script>
        (function () {
            sessionStorage.removeItem("vault_new_recovery_key");

            let loginPassword = sessionStorage.getItem("vault_login_password") || "";
            if (!loginPassword) {
                const entered = prompt("Enter your current login password to unlock your vault:");
                if (entered && entered.trim()) {
                    loginPassword = entered.trim();
                    sessionStorage.setItem("vault_login_password", loginPassword);
                }
            }
        })();
    </script>
    <script src="vault_crypto.js?v=300"></script>
    <script src="vault_page.js?v=302"></script>
</body>
</html>
