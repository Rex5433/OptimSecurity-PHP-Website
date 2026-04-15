<?php
include "db.php";
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>About This Project | Security Dashboard</title>
    <link rel="stylesheet" href="about.css">
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
                <a class="nav-link" href="phishing_toolkit.php">Phishing Toolkit</a>
                <a class="nav-link active" href="about.php">About Me</a>
            </div>

            <div class="sidebar-spacer"></div>

            <a class="nav-link" href="security_settings.php">Security Settings</a>
            <a class="nav-link" href="login.php">Logout</a>
        </aside>

        <main class="main-content">
            <div class="simple-page">
                <section class="simple-card page-hero">
                    <h1>About This Project</h1>
                    <p>
                        Welcome to the Senior Project Security Dashboard, a comprehensive cybersecurity toolkit
                        designed to provide users with practical security tools in one centralized platform.
                        This project combines secure design, modern web development, and user-friendly
                        functionality to make cybersecurity more accessible.
                    </p>
                    <p>
                        The dashboard is built to support password analysis, password generation, phishing awareness,
                        secure storage concepts, and account protection features. It is intended to demonstrate
                        both technical implementation and the importance of strong security practices in everyday use.
                    </p>
                </section>

                <section class="simple-card">
                    <h2>Project Overview</h2>
                    <p>
                        This security dashboard serves as a one-stop environment for common cybersecurity needs.
                        It focuses on blending usability with security so users can interact with important tools
                        without being overwhelmed by complexity.
                    </p>
                    <p>
                        The overall design follows a dark dashboard style for consistency across the project.
                        Each section is separated into clean cards so the interface feels organized, readable,
                        and visually aligned with the rest of the site.
                    </p>

                    <div class="stats-grid">
                        <div class="stat-item">
                            <div class="stat-number">6</div>
                            <div class="stat-label">Core Features</div>
                        </div>
                        <div class="stat-item">
                            <div class="stat-number">TOTP</div>
                            <div class="stat-label">2FA Support</div>
                        </div>
                        <div class="stat-item">
                            <div class="stat-number">24/7</div>
                            <div class="stat-label">Security Focus</div>
                        </div>
                        <div class="stat-item">
                            <div class="stat-number">UI</div>
                            <div class="stat-label">Dashboard Design</div>
                        </div>
                    </div>
                </section>

                <section class="simple-card">
                    <h2>Why Security Matters</h2>
                    <p>
                        In today’s digital world, cybersecurity affects nearly every user. Strong passwords,
                        phishing awareness, secure account protection, and safe data handling are no longer optional.
                        This project highlights those ideas through practical tools and a simple interface.
                    </p>

                    <div class="security-points">
                        <div class="security-point">
                            <h4>Protection First</h4>
                            <p>Every major feature is designed with security in mind from the start.</p>
                        </div>

                        <div class="security-point">
                            <h4>Usability Matters</h4>
                            <p>Security tools are more effective when users can understand and use them easily.</p>
                        </div>

                        <div class="security-point">
                            <h4>Learning by Using</h4>
                            <p>The dashboard helps users interact with real security concepts through direct use.</p>
                        </div>
                    </div>
                </section>

                <section class="simple-card">
                    <h2>Technology Stack</h2>

                    <div class="tech-grid">
                        <div class="tech-item">
                            <h4>Backend</h4>
                            <ul>
                                <li>PHP 8.x</li>
                                <li>PostgreSQL / Supabase</li>
                                <li>PDO for database access</li>
                            </ul>
                        </div>

                        <div class="tech-item">
                            <h4>Frontend</h4>
                            <ul>
                                <li>HTML5</li>
                                <li>CSS3</li>
                                <li>JavaScript</li>
                            </ul>
                        </div>

                        <div class="tech-item">
                            <h4>Security Features</h4>
                            <ul>
                                <li>Password tools</li>
                                <li>TOTP-based 2FA</li>
                                <li>Session handling</li>
                                <li>CSRF protection</li>
                            </ul>
                        </div>

                        <div class="tech-item">
                            <h4>Project Direction</h4>
                            <ul>
                                <li>User-friendly cybersecurity tools</li>
                                <li>Dark dashboard interface</li>
                                <li>Consistent layout design</li>
                                <li>Practical security education</li>
                            </ul>
                        </div>
                    </div>
                </section>

                <section class="simple-card">
                    <h2>Key Features</h2>

                    <div class="features-list">
                        <div class="feature-item">
                            <h4>Password Checker</h4>
                            <p>Evaluate password strength and encourage stronger password habits.</p>
                        </div>

                        <div class="feature-item">
                            <h4>Password Generator</h4>
                            <p>Create stronger passwords through a dedicated generation tool.</p>
                        </div>

                        <div class="feature-item">
                            <h4>Phishing Toolkit</h4>
                            <p>Support phishing awareness and suspicious content analysis.</p>
                        </div>

                        <div class="feature-item">
                            <h4>Vault Concepts</h4>
                            <p>Demonstrate secure storage ideas and user-focused protection features.</p>
                        </div>

                        <div class="feature-item">
                            <h4>2FA Protection</h4>
                            <p>Add another layer of account security using time-based verification codes.</p>
                        </div>

                        <div class="feature-item">
                            <h4>Unified Dashboard</h4>
                            <p>Keep all important security tools in one clean, consistent interface.</p>
                        </div>
                    </div>
                </section>

                <section class="simple-card">
                    <h2>Project Goals</h2>
                    <ul class="goals-list">
                        <li>Demonstrate practical cybersecurity concepts in a web-based project</li>
                        <li>Create accessible tools that encourage stronger security habits</li>
                        <li>Build a clean and organized dashboard-style user experience</li>
                        <li>Combine secure coding practices with real feature implementation</li>
                        <li>Present cybersecurity in a way that feels useful and approachable</li>
                    </ul>
                </section>

                <section class="simple-card">
                    <h2>Future Enhancements</h2>
                    <ul class="future-list">
                        <li>More advanced threat intelligence integrations</li>
                        <li>Expanded vault and account protection features</li>
                        <li>Improved reporting and monitoring widgets</li>
                        <li>Additional AI-assisted security functionality</li>
                        <li>Further layout and responsiveness improvements</li>
                    </ul>
                </section>
            </div>
        </main>
    </div>
</body>
</html>
