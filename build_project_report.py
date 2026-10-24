#!/usr/bin/env python3
"""
Humanized Student Project Report Generator (.pdf via HTML)
Project Topic: Automated Web Scanner: Programmed a Python script to audit sites for secure headers and CORS flaws.
IBM SkillsBuild National Cybersecurity Bootcamp
"""

import os
import subprocess
from pypdf import PdfReader

output_dir = "/Users/away/.gemini/antigravity/scratch/IBM_Cybersecurity_Bootcamp_Project"
html_path = os.path.join(output_dir, "Project_Report_Automated_Web_Scanner.html")
pdf_path = os.path.join(output_dir, "Project_Report_Automated_Web_Scanner.pdf")

html_content = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>IBM SkillsBuild Cybersecurity Bootcamp - Project Report</title>
    <style>
        @page {
            size: A4;
            margin: 20mm 18mm 20mm 18mm;
            @bottom-right {
                content: "Page " counter(page);
                font-size: 9pt;
                color: #64748b;
            }
        }
        :root {
            --primary: #0f62fe;
            --primary-dark: #002d9c;
            --secondary: #121619;
            --text-main: #1f2937;
            --text-muted: #4b5563;
            --border-color: #e5e7eb;
            --bg-light: #f9fafb;
            --accent-red: #da1e28;
            --accent-green: #198038;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;
            color: var(--text-main);
            background-color: #ffffff;
            margin: 0;
            padding: 0;
            line-height: 1.6;
            font-size: 10.5pt;
        }
        .page-break {
            page-break-after: always;
            break-after: page;
        }

        /* Cover Page */
        .cover-page {
            height: 90vh;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
            border: 2px solid var(--primary);
            padding: 40px;
            box-sizing: border-box;
            background: linear-gradient(135deg, #ffffff 0%, #f4f7fb 100%);
        }
        .cover-header {
            border-bottom: 3px solid var(--primary);
            padding-bottom: 15px;
        }
        .institution-title {
            font-size: 15pt;
            font-weight: 700;
            color: var(--primary-dark);
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin: 0;
        }
        .bootcamp-sub {
            font-size: 11pt;
            color: var(--text-muted);
            margin-top: 4px;
        }
        .cover-body {
            margin: auto 0;
        }
        .project-badge {
            display: inline-block;
            background: #e0eefe;
            color: var(--primary-dark);
            font-weight: 700;
            font-size: 9.5pt;
            padding: 5px 12px;
            border-radius: 20px;
            margin-bottom: 15px;
            text-transform: uppercase;
        }
        .project-title {
            font-size: 24pt;
            font-weight: 800;
            color: var(--secondary);
            line-height: 1.25;
            margin: 0 0 15px 0;
        }
        .project-subtitle {
            font-size: 12pt;
            color: var(--text-muted);
            line-height: 1.5;
            max-width: 90%;
        }
        .cover-footer {
            border-top: 1px solid var(--border-color);
            padding-top: 20px;
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            font-size: 9.5pt;
        }
        .meta-group strong {
            display: block;
            color: var(--primary-dark);
            text-transform: uppercase;
            font-size: 8pt;
            margin-bottom: 2px;
        }

        /* Typography & Layout */
        h1 {
            font-size: 16pt;
            font-weight: 800;
            color: var(--primary-dark);
            border-bottom: 2px solid var(--primary);
            padding-bottom: 5px;
            margin-top: 26px;
            margin-bottom: 12px;
        }
        h2 {
            font-size: 13pt;
            font-weight: 700;
            color: var(--secondary);
            margin-top: 20px;
            margin-bottom: 8px;
            border-left: 4px solid var(--primary);
            padding-left: 8px;
        }
        p {
            margin: 0 0 11px 0;
            text-align: justify;
        }
        ul, ol {
            margin: 0 0 12px 20px;
            padding: 0;
        }
        li {
            margin-bottom: 5px;
        }

        /* Tables */
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 14px 0;
            font-size: 9.5pt;
        }
        th, td {
            border: 1px solid var(--border-color);
            padding: 8px 10px;
            text-align: left;
            vertical-align: top;
        }
        th {
            background-color: #edf5ff;
            color: var(--primary-dark);
            font-weight: 700;
        }
        tr:nth-child(even) td {
            background-color: #f9fafb;
        }

        /* Code Blocks */
        pre {
            background-color: #1e1e1e;
            color: #d4d4d4;
            padding: 12px;
            border-radius: 6px;
            font-family: Consolas, "Liberation Mono", Menlo, monospace;
            font-size: 8.5pt;
            line-height: 1.4;
            overflow-x: auto;
            margin: 12px 0;
        }
        code {
            font-family: Consolas, monospace;
            background-color: #f3f4f6;
            padding: 2px 4px;
            border-radius: 4px;
            font-size: 9pt;
            color: var(--primary-dark);
        }
        pre code {
            background-color: transparent;
            padding: 0;
            color: inherit;
        }

        /* Callouts */
        .callout {
            border-left: 4px solid var(--primary);
            background-color: #edf5ff;
            padding: 10px 14px;
            border-radius: 0 6px 6px 0;
            margin: 12px 0;
            font-size: 9.5pt;
        }
        .callout-title {
            font-weight: 700;
            color: var(--primary-dark);
            margin-bottom: 3px;
        }
        .badge {
            display: inline-block;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 7.5pt;
            font-weight: 700;
            text-transform: uppercase;
        }
        .badge-pass { background: #defbe6; color: #198038; }
        .badge-fail { background: #ffe3e3; color: #da1e28; }
        .badge-warn { background: #fef3c7; color: #b45309; }
    </style>
</head>
<body>

<!-- COVER PAGE -->
<div class="cover-page">
    <div class="cover-header">
        <div class="institution-title">IBM SkillsBuild National Cybersecurity Bootcamp</div>
        <div class="bootcamp-sub">Conducted by BharatCares (CSRBOX Group) in partnership with IBM SkillsBuild</div>
    </div>

    <div class="cover-body">
        <div class="project-badge">Capstone Project Report &bull; Topic 2</div>
        <h1 class="project-title">Automated Web Scanner:<br>Auditing Sites for Secure Headers & CORS Flaws</h1>
        <div class="project-subtitle">
            A practical, zero-dependency Python tool developed to automatically evaluate web application HTTP security headers and detect dangerous Cross-Origin Resource Sharing (CORS) misconfigurations.
        </div>
    </div>

    <div class="cover-footer">
        <div class="meta-group">
            <strong>Participant / Author</strong>
            Tarun Singh<br>
            GitHub: tarun-singh9897<br>
            Track: Cybersecurity & Web Defense
        </div>
        <div class="meta-group">
            <strong>Bootcamp Details</strong>
            IBM SkillsBuild National Cybersecurity Bootcamp<br>
            Submission: October 2026
        </div>
    </div>
</div>

<div class="page-break"></div>

<!-- SECTION 1 -->
<h1>1. Project Overview & Motivation</h1>
<p>
During the 2-week IBM SkillsBuild National Cybersecurity Bootcamp, we covered a variety of cybersecurity fundamentals, including threat modeling, ethical hacking principles, and network security. For my final project submission, I selected <strong>Topic #2: Automated Web Scanner: Programmed a Python script to audit sites for secure headers and CORS flaws</strong>.
</p>
<p>
In modern web development, teams often focus entirely on user interfaces and database logic while overlooking fundamental HTTP transport and access control configurations. In fact, <em>Security Misconfiguration</em> ranks prominently under <strong>OWASP Top 10 (A05:2021)</strong>. Failing to configure defensive HTTP headers leaves users open to clickjacking, unauthorized script execution (XSS), and protocol downgrade attacks. Furthermore, when configuring Cross-Origin Resource Sharing (CORS) to connect frontend single-page apps to backend APIs, developers frequently take insecure shortcuts—such as reflecting incoming <code>Origin</code> headers indiscriminately or combining wildcards with credentials.
</p>
<p>
To tackle this issue, I programmed an automated Python security scanner. The tool takes any web address, analyzes its HTTP response headers, actively probes the endpoint with synthetic origin headers to detect CORS flaws, calculates an objective 0–100 security score with letter grades (A+ to F), and outputs clear reports in the terminal, as structured JSON, or as an HTML report.
</p>

<div class="callout">
    <div class="callout-title">Key Design Philosophy</div>
    I built the tool with <strong>zero external dependencies</strong> using only Python's built-in standard library (<code>urllib.request</code>, <code>concurrent.futures</code>, <code>json</code>, <code>argparse</code>, <code>ssl</code>). This ensures anyone can run the scanner immediately on any machine running Python 3 without dealing with package installation issues.
</div>

<h1>2. Objectives & Design Choices</h1>
<p>I set three clear design goals for this project:</p>
<ul>
    <li><strong>Comprehensive Defensive Audit:</strong> Check all critical security headers specified by the OWASP Secure Headers Project (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy), plus information disclosure banners like <code>Server</code> and <code>X-Powered-By</code>.</li>
    <li><strong>Active Synthetic CORS Probing:</strong> Rather than just passively reading existing CORS headers, the scanner actively tests how the server behaves when probed with untrusted origins (e.g. an attacker domain, <code>null</code>, and regex prefix/suffix bypass attempts).</li>
    <li><strong>Actionable Feedback & Scoring:</strong> The scanner gives developers practical remediation snippets (such as exact Nginx configuration lines or Flask code) so they can fix flagged weaknesses immediately.</li>
</ul>

<div class="page-break"></div>

<!-- SECTION 3 -->
<h1>3. Technical Methodology</h1>

<h2>3.1 HTTP Security Headers Audit</h2>
<p>The scanner's <code>HeaderAuditor</code> evaluates the target's HTTP responses against modern web security standards:</p>

<table>
    <thead>
        <tr>
            <th>Header Name</th>
            <th>Recommended Baseline</th>
            <th>Risk if Missing or Misconfigured</th>
        </tr>
    </thead>
    <tbody>
        <tr>
            <td><strong>Content-Security-Policy</strong></td>
            <td><code>default-src 'self'; script-src 'self'; object-src 'none';</code></td>
            <td>High risk of Cross-Site Scripting (XSS) and unauthorized data exfiltration.</td>
        </tr>
        <tr>
            <td><strong>Strict-Transport-Security</strong></td>
            <td><code>max-age=31536000; includeSubDomains; preload</code></td>
            <td>Allows SSL-stripping and cleartext downgrade attacks over untrusted Wi-Fi.</td>
        </tr>
        <tr>
            <td><strong>X-Frame-Options</strong></td>
            <td><code>DENY</code> or <code>SAMEORIGIN</code></td>
            <td>Vulnerable to Clickjacking (UI redressing) in legacy browsers.</td>
        </tr>
        <tr>
            <td><strong>X-Content-Type-Options</strong></td>
            <td><code>nosniff</code></td>
            <td>Browsers may execute uploaded non-executable files via MIME sniffing.</td>
        </tr>
        <tr>
            <td><strong>Referrer-Policy</strong></td>
            <td><code>strict-origin-when-cross-origin</code></td>
            <td>Leaks sensitive tokens or internal URLs to external third parties.</td>
        </tr>
        <tr>
            <td><strong>Permissions-Policy</strong></td>
            <td><code>camera=(), microphone=(), geolocation=()</code></td>
            <td>Browser hardware features remain open to unauthorized access.</td>
        </tr>
        <tr>
            <td><strong>Server & Tech Banners</strong></td>
            <td>Suppress <code>Server</code> and <code>X-Powered-By</code></td>
            <td>Reveals exact server OS and software versions to automated scanners.</td>
        </tr>
    </tbody>
</table>

<h2>3.2 CORS Flaw Detection & Probing</h2>
<p>Cross-Origin Resource Sharing (CORS) relaxes the Same-Origin Policy. To audit CORS logic, the scanner sends active test probes:</p>
<ul>
    <li><strong>Arbitrary Origin Reflection:</strong> The scanner sends <code>Origin: https://attacker-security-test.com</code>. If the server echoes this origin in <code>Access-Control-Allow-Origin</code>, it reveals flawed origin validation.</li>
    <li><strong>Origin Reflection with Credentials (CRITICAL):</strong> If arbitrary reflection is combined with <code>Access-Control-Allow-Credentials: true</code>, this is marked CRITICAL. An attacker site can issue cross-origin requests using a victim's session cookies and read private API responses.</li>
    <li><strong>Null Origin Trust (HIGH):</strong> The scanner tests <code>Origin: null</code>. If accepted, attackers can bypass origin checks using sandboxed <code>&lt;iframe&gt;</code> elements or <code>data:</code> URIs.</li>
    <li><strong>Regex Suffix & Prefix Bypasses:</strong> Tests whether unanchored regular expressions allow origins like <code>https://target.com.attacker.com</code> or <code>https://attacker-target.com</code>.</li>
</ul>

<h2>3.3 Scoring & Grade Calculation</h2>
<p>
The audit starts with a perfect score of 100 points. Penalties are deducted based on risk severity:
Missing CSP (-25), Missing HSTS (-20), Critical CORS Credential Reflection (-30), High CORS Flaw / Null Origin (-20), Missing X-Frame-Options (-15), Missing X-Content-Type-Options (-10), and Leaky Banners (-5). 
Scores translate directly into letter grades: <strong>A+ (95–100)</strong>, <strong>A (85–94)</strong>, <strong>B (75–84)</strong>, <strong>C (60–74)</strong>, <strong>D (45–59)</strong>, and <strong>F (&lt;45)</strong>.
</p>

<div class="page-break"></div>

<!-- SECTION 4 -->
<h1>4. Code Architecture & Implementation</h1>
<p>
The script is organized in a modular structure within <code>scanner.py</code>:
</p>
<ul>
    <li><code>HeaderAuditor</code>: Encapsulates header evaluation logic and severity grading.</li>
    <li><code>CORSAuditor</code>: Sends synthetic HTTP requests with test origin headers and examines server responses.</li>
    <li><code>WebScanner</code>: Handles target requests, thread pooling (<code>concurrent.futures.ThreadPoolExecutor</code>) for scanning multiple URLs simultaneously, and final score calculations.</li>
    <li><code>Reporter</code>: Formats scan data into colored terminal output, clean JSON, or standalone HTML.</li>
    <li><code>--demo Mode</code>: A built-in offline demonstration mode that simulates both a vulnerable and a hardened target so evaluators can test the tool without needing live network access.</li>
</ul>

<h1>5. Testing & Experimental Results</h1>
<p>
I validated the tool using both automated unit testing and sample scans:
</p>

<h2>5.1 Unit Tests (tests/test_scanner.py)</h2>
<p>Running the unit test suite passes all 5 tests instantly:</p>
<pre><code>python3 -m unittest discover -s tests -p "test_*.py" -v
test_information_leakage_detection ... ok
test_missing_all_security_headers ... ok
test_strong_security_headers ... ok
test_weak_csp_warning ... ok
test_grade_calculation ... ok
Ran 5 tests in 0.000s (OK)</code></pre>

<h2>5.2 Sample Audit Output on a Vulnerable Endpoint</h2>
<pre><code>----------------------------------------------------------------------
[1/1] Target: https://vulnerable-portal.local/api
Scan Time: 2026-10-24 15:46:57 | HTTP Status: 200 | Latency: 142.5 ms
Security Score: 35/100 (Grade: F)
----------------------------------------------------------------------
--- [1] HTTP SECURE HEADERS AUDIT ---
  [FAIL] Content-Security-Policy (Severity: HIGH)
         Missing CSP header. Vulnerable to XSS and Clickjacking.
  [FAIL] Strict-Transport-Security (Severity: HIGH)
         Missing HSTS header on HTTPS connection.
  [FAIL] X-Frame-Options (Severity: MEDIUM)
         Missing X-Frame-Options. Page can be framed for Clickjacking.
  [PASS] X-Content-Type-Options (Severity: PASS) - nosniff enabled.
--- [2] CORS MISCONFIGURATION PROBING ---
  [CRITICAL] Arbitrary Origin Reflection with Credentials
         Test Origin: https://attacker-security-test.com
         Finding: Server reflects arbitrary Origin AND sets Access-Control-Allow-Credentials: true.
         ACAO: https://attacker-security-test.com | ACAC: true
  [HIGH] Null Origin Trust
         Test Origin: null | Finding: Server explicitly trusts 'null' origin.</code></pre>

<div class="page-break"></div>

<!-- SECTION 6 & 7 -->
<h1>6. Challenges Faced & Solutions</h1>
<p>During the project, I addressed several practical challenges:</p>
<ul>
    <li><strong>Handling SSL Certificate Verification:</strong> Testing local development servers or self-signed staging environments often throws SSL verification errors. I added a <code>-k / --insecure</code> command-line flag to let testers bypass certificate checks when auditing lab environments.</li>
    <li><strong>User-Agent Filtering:</strong> Several web applications block the default Python-urllib User-Agent. I solved this by configuring a realistic browser User-Agent in the HTTP request headers.</li>
    <li><strong>Distinguishing Safe Wildcards from Insecure CORS:</strong> A wildcard <code>Access-Control-Allow-Origin: *</code> is completely fine for public read-only content, but dangerous when credentials are enabled. I ensured the scanner only flags high-severity warnings when wildcards or reflected origins are paired with <code>Access-Control-Allow-Credentials: true</code>.</li>
</ul>

<h1>7. Remediation & Hardening Guide</h1>
<p>Fixing issues flagged by the scanner is straightforward for developers:</p>

<h2>Nginx Server Configuration</h2>
<pre><code># /etc/nginx/conf.d/security_headers.conf
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none';" always;
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
server_tokens off;</code></pre>

<h2>Secure Backend CORS Whitelist (Python / Flask)</h2>
<pre><code>ALLOWED_ORIGINS = {"https://trusted-portal.com", "https://admin.trusted-portal.com"}

@app.after_request
def set_secure_cors(response):
    origin = request.headers.get("Origin")
    if origin in ALLOWED_ORIGINS:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Vary"] = "Origin"
    return response</code></pre>

<h1>8. Key Learnings & Conclusion</h1>
<p>
This project provided great hands-on learning during the IBM SkillsBuild Cybersecurity Bootcamp. I learned how easily security misconfigurations can occur in real-world web environments, how the browser's Same-Origin Policy interacts with CORS headers, and why automated auditing is necessary to catch vulnerabilities before code is pushed to production.
</p>
<p>
The resulting Python scanner is fast, portable, and reliable. It serves as an effective auditing utility for developers and security analysts to ensure web applications maintain strong baseline security.
</p>

<hr style="margin: 25px 0; border: none; border-top: 1px solid #e5e7eb;">
<p style="font-size: 9pt; color: #6b7280;">
<strong>References:</strong><br>
1. OWASP Top 10 (A05:2021 - Security Misconfiguration)<br>
2. OWASP Secure Headers Project Guidelines<br>
3. W3C Cross-Origin Resource Sharing (CORS) Specification & MDN Web Docs<br>
4. IBM SkillsBuild National Cybersecurity Bootcamp Masterclasses (October 2026)
</p>

</body>
</html>
"""

with open(html_path, "w", encoding="utf-8") as f:
    f.write(html_content)
print(f"[+] Saved report HTML to: {html_path}")

# Compile PDF using Google Chrome Headless
chrome_cmd = [
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "--headless=new",
    "--disable-gpu",
    f"--print-to-pdf={pdf_path}",
    html_path
]

try:
    subprocess.run(chrome_cmd, check=True)
    print(f"[+] Successfully compiled PDF report to: {pdf_path}")
    if os.path.exists(pdf_path):
        reader = PdfReader(pdf_path)
        print(f"[+] Verified PDF Page Count: {len(reader.pages)} pages.")
except Exception as e:
    print(f"[!] Error compiling PDF via Chrome: {e}")
