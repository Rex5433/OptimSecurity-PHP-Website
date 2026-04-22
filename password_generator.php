<?php
include "db.php";
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Password Generator | Optimsecurity</title>
    <link rel="stylesheet" href="password_generator.css?v=2">
    <link rel="icon" href="/favicon.ico" type="image/x-icon">

    <link rel="icon" type="image/png" sizes="32x32" href="/favicon-32x32.png">
    <link rel="icon" type="image/png" sizes="16x16" href="/favicon-16x16.png">

    <link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png">
    <link rel="manifest" href="/site.webmanifest">
</head>
<body class="generator-body">
    <div class="generator-shell">
        <aside class="generator-sidebar">
            <div class="generator-sidebar-title">Dashboard</div>

            <nav class="generator-nav">
                <a href="homepage.php" class="generator-nav-item">Home</a>
                <a href="password_checker.php" class="generator-nav-item">Password Check</a>
                <a href="password_generator.php" class="generator-nav-item active">Password Gen</a>
                <a href="vault.php" class="generator-nav-item">Vault</a>
                <a href="phishing_toolkit.php" class="generator-nav-item">Phishing Toolkit</a>
                <a href="about.php" class="generator-nav-item">About Me</a>

                <div class="generator-sidebar-spacer"></div>

                <a href="security_settings.php" class="generator-nav-item">Security Settings</a>
                <a href="logout.php" class="generator-nav-item logout">Logout</a>
            </nav>
        </aside>

        <main class="generator-main">
            <section class="generator-hero-card">
                <div class="generator-badge">Password Generator</div>
                <h1>Generate a secure password</h1>
                <p>
                    Generates strong and memorable passwords using Neural Input Optimization logic.
                </p>
            </section>

            <section class="generator-grid">
                <div class="generator-card">
                    <div class="generator-card-header">
                        <h2>Generator Settings</h2>
                        <p>Keep the design the same while sending settings that match the FastAPI backend.</p>
                    </div>

                    <form class="generator-form" id="generatorForm">
                        <div class="generator-form-group">
                            <label for="keywordInput">Keyword / Custom Word</label>
                            <input
                                type="text"
                                id="keywordInput"
                                placeholder="Example: BettaFish, Dragon, Night"
                            >
                        </div>

                        <div class="generator-form-group">
                            <label for="passwordLength">Password Length (8 to 32)</label>
                            <input
                                type="number"
                                id="passwordLength"
                                value="16"
                                min="8"
                                max="32"
                            >
                        </div>

                        <div class="generator-form-group">
                            <label>Passwords to Generate</label>
                            <div class="generator-count-buttons" id="candidateCountButtons">
                                <button type="button" class="generator-count-btn" data-value="1">1</button>
                                <button type="button" class="generator-count-btn" data-value="2">2</button>
                                <button type="button" class="generator-count-btn active" data-value="3">3</button>
                                <button type="button" class="generator-count-btn" data-value="4">4</button>
                                <button type="button" class="generator-count-btn" data-value="5">5</button>
                            </div>
                            <input type="hidden" id="candidateCount" value="3">
                        </div>

                        <div class="generator-form-group">
                            <label for="allowDigits" class="generator-check-label">
                                <input
                                    type="checkbox"
                                    id="allowDigits"
                                    checked
                                >
                                Allow Digits
                            </label>
                        </div>

                        <div class="generator-form-group">
                            <label for="allowSymbols" class="generator-check-label">
                                <input
                                    type="checkbox"
                                    id="allowSymbols"
                                    checked
                                >
                                Allow Symbols
                            </label>
                        </div>

                        <div class="generator-button-row">
                            <button type="submit" class="generator-btn" id="generateBtn">
                                Generate Password
                            </button>
                        </div>
                    </form>
                </div>

                <div class="generator-card">
                    <div class="generator-card-header">
                        <h2>Generated Passwords</h2>
                        <p>Your generated password candidates will appear here.</p>
                    </div>

                    <div class="generator-result-box">
                        <div class="generator-result-title">Generated Passwords</div>

                        <div id="topMessage" class="generator-empty">
                            Generate a password to see the results here.
                        </div>

                        <div id="bottomMessage" class="generator-empty">
                            Waiting for generation...
                        </div>

                        <div id="resultBox" class="generator-result-display" style="display: none;"></div>
                    </div>
                </div>
            </section>

            <section class="generator-card">
                <div class="generator-card-header">
                    <h2>How This Generator Works</h2>
                    <p>These are the general ideas used when generating a password.</p>
                </div>

                <div class="generator-tips-grid">
                    <div class="generator-tip-box">
                        <h3>Keyword Input</h3>
                        <p>
                            The generator uses your custom word as the base idea for the password.
                            If no keyword is entered, a fallback keyword can be used by the backend.
                        </p>
                    </div>

                    <div class="generator-tip-box">
                        <h3>Displayed Result</h3>
                        <p>
                            Each result shows the generated password, memorability score, final strength label,
                            and the active keyword used during generation.
                        </p>
                    </div>

                    <div class="generator-tip-box">
                        <h3>Password Check</h3>
                        <p>
                            Use the Password Check page if you want to test your own custom password directly.
                        </p>
                    </div>
                </div>
            </section>
        </main>
    </div>

    <script>
        const form = document.getElementById("generatorForm");
        const generateBtn = document.getElementById("generateBtn");
        const API_URL = "/generate_passwords_proxy.php";
        const candidateCountInput = document.getElementById("candidateCount");
        const candidateCountButtons = document.querySelectorAll(".generator-count-btn");

        candidateCountButtons.forEach(function (button) {
            button.addEventListener("click", function () {
                candidateCountButtons.forEach(function (btn) {
                    btn.classList.remove("active");
                });
                button.classList.add("active");
                candidateCountInput.value = button.dataset.value;
            });
        });

        function setIdleState() {
            resetMessageStyles();
            document.getElementById("topMessage").style.display = "block";
            document.getElementById("bottomMessage").style.display = "block";
            document.getElementById("resultBox").style.display = "none";

            document.getElementById("topMessage").textContent = "Generate a password to see the results here.";
            document.getElementById("bottomMessage").textContent = "Waiting for generation...";
        }

        function setLoadingState() {
            resetMessageStyles();
            document.getElementById("topMessage").style.display = "none";
            document.getElementById("bottomMessage").style.display = "none";
            document.getElementById("resultBox").style.display = "none";
        }

        function setErrorState(message) {
            const topMessage = document.getElementById("topMessage");
            const bottomMessage = document.getElementById("bottomMessage");

            document.getElementById("resultBox").style.display = "none";

            topMessage.style.display = "block";
            bottomMessage.style.display = "block";

            topMessage.textContent = "Generation failed.";
            bottomMessage.textContent = message || "Something went wrong.";

            topMessage.className = "generator-empty generator-error";
            bottomMessage.className = "generator-empty generator-error";
        }

        function resetMessageStyles() {
            document.getElementById("topMessage").className = "generator-empty";
            document.getElementById("bottomMessage").className = "generator-empty";
        }

        function pillClassFromLabel(labelText) {
            const lower = String(labelText || "").toLowerCase();

            if (lower.includes("weak")) {
                return "generator-pill weak";
            }

            if (lower.includes("average")) {
                return "generator-pill medium";
            }

            return "generator-pill strong";
        }

        function safeText(value, fallback = "--") {
            if (value === null || value === undefined || value === "") {
                return fallback;
            }
            return value;
        }

        function escapeHtml(value) {
            return String(value)
                .replace(/&/g, "&amp;")
                .replace(/</g, "&lt;")
                .replace(/>/g, "&gt;")
                .replace(/"/g, "&quot;")
                .replace(/'/g, "&#39;");
        }

        function copyToClipboard(text, button) {
            if (navigator.clipboard && window.isSecureContext) {
                navigator.clipboard.writeText(text).then(function () {
                    button.classList.add("copied");

                    setTimeout(function () {
                        button.classList.remove("copied");
                    }, 1000);
                }).catch(function () {
                    fallbackCopy(text, button);
                });
            } else {
                fallbackCopy(text, button);
            }
        }

        function fallbackCopy(text, button) {
            const textArea = document.createElement("textarea");
            textArea.value = text;
            textArea.style.position = "fixed";
            textArea.style.opacity = "0";
            document.body.appendChild(textArea);
            textArea.focus();
            textArea.select();

            try {
                document.execCommand("copy");
                button.classList.add("copied");

                setTimeout(function () {
                    button.classList.remove("copied");
                }, 1000);
            } catch (err) {
                console.error("Copy failed.");
            }

            document.body.removeChild(textArea);
        }

        function renderResults(data, userWords) {
            resetMessageStyles();

            const topMessage = document.getElementById("topMessage");
            const bottomMessage = document.getElementById("bottomMessage");
            const resultBox = document.getElementById("resultBox");

            const items = Array.isArray(data.results) ? data.results : [];

            if (items.length === 0) {
                topMessage.style.display = "block";
                bottomMessage.style.display = "block";
                resultBox.style.display = "none";

                topMessage.textContent = "No password generated.";
                bottomMessage.textContent = safeText(data.message, "Try again.");
                return;
            }

            topMessage.style.display = "none";
            bottomMessage.style.display = "none";
            resultBox.style.display = "block";

            if ((!userWords || userWords.length === 0) && data.active_keyword) {
                document.getElementById("keywordInput").value = data.active_keyword;
            }

            let displayMessage = safeText(
                data.message,
                `${safeText(data.returned_count, 0)} of ${safeText(data.requested_count, 0)} password candidate(s) returned.`
            );

            if (data.used_fallback_keyword && typeof displayMessage === "string") {
                displayMessage = displayMessage.replace(
                    /No keyword was provided, so the generator used fallback keyword '.*?'\.?\s*/i,
                    ""
                ).trim();
            }

            bottomMessage.textContent =
                displayMessage ||
                `${safeText(data.returned_count, 0)} of ${safeText(data.requested_count, 0)} password candidate(s) returned.`;

            resultBox.innerHTML = "";

            items.forEach(function (item, index) {
                const card = document.createElement("div");
                card.className = "generator-password-card";

                const finalLabel = item.strength || item.adjusted_label || item.cnn_label;
                const safePassword = safeText(item.password, "");
                const escapedPassword = escapeHtml(safePassword);
                const escapedKeyword = escapeHtml(safeText(item.active_keyword, "--"));
                const escapedLabel = escapeHtml(safeText(finalLabel, "--"));

                card.innerHTML = `
                    <div class="generator-password-header">
                        <div class="generator-password-main">
                            <div class="generator-result-title small">Generated Password ${index + 1}</div>

                            <div class="generator-password-line">
                                <div class="generator-result-value">${escapedPassword}</div>

                                <button
                                    type="button"
                                    class="generator-copy-icon-btn"
                                    aria-label="Copy password"
                                    title="Copy password"
                                >
                                    <span class="generator-copy-icon" aria-hidden="true"></span>
                                </button>
                            </div>
                        </div>

                        <span class="${pillClassFromLabel(finalLabel)}">${escapedLabel}</span>
                    </div>

                    <div class="generator-stats-row clean" style="margin-top: 14px;">
                        <div class="generator-stat-box">
                            <span class="generator-stat-label">Memorability</span>
                            <span class="generator-stat-value">${item.memorability != null ? Number(item.memorability).toFixed(2) + "%" : "--"}</span>
                        </div>

                        <div class="generator-stat-box">
                            <span class="generator-stat-label">Active Keyword</span>
                            <span class="generator-stat-value">${escapedKeyword}</span>
                        </div>
                    </div>
                `;

                resultBox.appendChild(card);

                const copyBtn = card.querySelector(".generator-copy-icon-btn");

                if (copyBtn) {
                    copyBtn.addEventListener("click", function () {
                        copyToClipboard(safePassword, copyBtn);
                    });
                }
            });
        }

        form.addEventListener("submit", async function (event) {
            event.preventDefault();

            resetMessageStyles();

            const userWords = document.getElementById("keywordInput").value.trim();
            const length = parseInt(document.getElementById("passwordLength").value, 10);
            const topK = parseInt(document.getElementById("candidateCount").value, 10);
            const allowDigits = document.getElementById("allowDigits").checked;
            const allowSymbols = document.getElementById("allowSymbols").checked;

            if (Number.isNaN(length) || length < 8 || length > 32) {
                setErrorState("Enter a valid password length between 8 and 32.");
                return;
            }

            if (Number.isNaN(topK) || topK < 1 || topK > 5) {
                setErrorState("Enter a valid password count between 1 and 5.");
                return;
            }

            generateBtn.disabled = true;
            generateBtn.textContent = "Generating...";
            setLoadingState();

            try {
                const response = await fetch(API_URL, {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json"
                    },
                    body: JSON.stringify({
                        user_words: userWords,
                        length: length,
                        top_k: topK,
                        memorability_target: 80,
                        allow_digits: allowDigits,
                        allow_symbols: allowSymbols,
                        preserve_input: true
                    })
                });

                const rawText = await response.text();

                let data = {};
                try {
                    data = JSON.parse(rawText);
                } catch (e) {
                    throw new Error(rawText || "Backend returned invalid JSON.");
                }

                if (!response.ok) {
                    throw new Error(data.detail || data.message || rawText || "Backend request failed.");
                }

                if (!data.results || !Array.isArray(data.results)) {
                    throw new Error("Invalid backend response.");
                }

                renderResults(data, userWords);
            } catch (error) {
                setErrorState(error.message);
            } finally {
                generateBtn.disabled = false;
                generateBtn.textContent = "Generate Password";
            }
        });

        setIdleState();
    </script>
</body>
</html>
