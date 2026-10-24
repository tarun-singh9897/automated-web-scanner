#!/usr/bin/env python3
"""
Humanized Student Project Report Generator (.docx)
Project Topic: Automated Web Scanner: Programmed a Python script to audit sites for secure headers and CORS flaws.
IBM SkillsBuild National Cybersecurity Bootcamp
"""

import os
import docx
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml import parse_xml
from docx.oxml.ns import nsdecls

output_dir = os.path.dirname(os.path.abspath(__file__))
doc = docx.Document()

# Margins: Standard 1 inch
for section in doc.sections:
    section.top_margin = Inches(1.0)
    section.bottom_margin = Inches(1.0)
    section.left_margin = Inches(1.0)
    section.right_margin = Inches(1.0)

# Colors
COLOR_DARK = RGBColor(0, 45, 156)      # Navy #002D9C
COLOR_PRIMARY = RGBColor(15, 98, 254)  # IBM Blue #0F62FE
COLOR_TEXT = RGBColor(30, 30, 30)      # Charcoal
COLOR_MUTED = RGBColor(100, 100, 100)

style_normal = doc.styles['Normal']
style_normal.font.name = 'Calibri'
style_normal.font.size = Pt(11)
style_normal.font.color.rgb = COLOR_TEXT
style_normal.paragraph_format.line_spacing = 1.2
style_normal.paragraph_format.space_after = Pt(6)

def add_heading_1(text):
    h = doc.add_heading(text, level=1)
    h.paragraph_format.space_before = Pt(16)
    h.paragraph_format.space_after = Pt(6)
    for r in h.runs:
        r.font.name = 'Calibri'
        r.font.size = Pt(15)
        r.font.bold = True
        r.font.color.rgb = COLOR_DARK
    return h

def add_heading_2(text):
    h = doc.add_heading(text, level=2)
    h.paragraph_format.space_before = Pt(12)
    h.paragraph_format.space_after = Pt(4)
    for r in h.runs:
        r.font.name = 'Calibri'
        r.font.size = Pt(12.5)
        r.font.bold = True
        r.font.color.rgb = COLOR_PRIMARY
    return h

def add_callout(text, title="NOTE"):
    tbl = doc.add_table(rows=1, cols=1)
    tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
    cell = tbl.cell(0, 0)
    cell.width = Inches(6.5)
    shd = f'<w:shd {nsdecls("w")} w:fill="F4F6FB"/>'
    borders = f'<w:tcBorders {nsdecls("w")}><w:left w:val="single" w:sz="20" w:space="0" w:color="0F62FE"/><w:top w:val="none"/><w:right w:val="none"/><w:bottom w:val="none"/></w:tcBorders>'
    cell._tc.get_or_add_tcPr().append(parse_xml(shd))
    cell._tc.get_or_add_tcPr().append(parse_xml(borders))
    p = cell.paragraphs[0]
    p.paragraph_format.space_before = Pt(4)
    p.paragraph_format.space_after = Pt(4)
    r_t = p.add_run(f"[{title}] ")
    r_t.font.bold = True
    r_t.font.size = Pt(10)
    r_t.font.color.rgb = COLOR_DARK
    r_b = p.add_run(text)
    r_b.font.size = Pt(10)
    doc.add_paragraph()

# ================= TITLE & COVER SECTION =================
p_title = doc.add_paragraph()
p_title.alignment = WD_ALIGN_PARAGRAPH.CENTER
p_title.paragraph_format.space_before = Pt(24)
p_title.paragraph_format.space_after = Pt(6)

r_org = p_title.add_run("IBM SKILLSBUILD NATIONAL CYBERSECURITY BOOTCAMP\n")
r_org.font.bold = True
r_org.font.size = Pt(13)
r_org.font.color.rgb = COLOR_DARK

r_sub = p_title.add_run("Conducted by BharatCares (CSRBOX Group) in collaboration with IBM SkillsBuild\n\n")
r_sub.font.size = Pt(10.5)
r_sub.font.color.rgb = COLOR_MUTED

r_tag = p_title.add_run("FINAL PROJECT REPORT\n")
r_tag.font.bold = True
r_tag.font.size = Pt(11)
r_tag.font.color.rgb = COLOR_PRIMARY

r_main = p_title.add_run("Automated Web Scanner:\nAudit Sites for Secure Headers and CORS Flaws\n")
r_main.font.bold = True
r_main.font.size = Pt(20)
r_main.font.color.rgb = COLOR_TEXT

p_meta = doc.add_paragraph()
p_meta.alignment = WD_ALIGN_PARAGRAPH.CENTER
p_meta.paragraph_format.space_before = Pt(20)
p_meta.paragraph_format.space_after = Pt(24)
r_m = p_meta.add_run(
    "Project Topic #2: Automated Web Scanner\n"
    "Participant: Tarun Singh\n"
    "GitHub: tarun-singh9897\n"
    "Track: Cybersecurity & Web Defense\n"
    "Date: October 2026"
)
r_m.font.size = Pt(10)
r_m.font.color.rgb = COLOR_MUTED

doc.add_page_break()

# ================= 1. PROJECT OVERVIEW =================
add_heading_1("1. Project Overview & Motivation")
doc.add_paragraph(
    "During the 2-week IBM SkillsBuild Cybersecurity Bootcamp, we explored core attack surfaces and defense strategies, "
    "ranging from phishing analysis and network defense to web application vulnerabilities. For my capstone project, "
    "I chose Topic #2: 'Automated Web Scanner: Programmed a Python script to audit sites for secure headers and CORS flaws.'"
)
doc.add_paragraph(
    "When building or deploying web applications, developers often focus entirely on functionality and database queries, "
    "frequently forgetting basic HTTP configuration hardening. Leaving out headers like Content-Security-Policy or "
    "Strict-Transport-Security leaves users exposed to clickjacking, protocol downgrades, and Cross-Site Scripting (XSS). "
    "Even worse, when configuring Cross-Origin Resource Sharing (CORS), developers frequently reflect whatever Origin "
    "comes in from the browser or enable credentials with wildcards to 'just make it work'. This completely breaks the "
    "browser's Same-Origin Policy and allows malicious sites to steal user data."
)
doc.add_paragraph(
    "My goal in this project was to write a practical, lightweight, and automated Python scanner that can take any website URL, "
    "evaluate all of its HTTP security headers, actively probe it for CORS vulnerabilities, calculate a clear security score "
    "(from 0 to 100 with a letter grade), and produce easy-to-read reports in the terminal, as JSON, or as an HTML report."
)

# ================= 2. OBJECTIVES & DESIGN DECISIONS =================
add_heading_1("2. Objectives & Design Choices")
doc.add_paragraph("I designed the scanner around three main technical goals:")
doc.add_paragraph(
    "1. Zero External Dependencies: I decided to write the entire tool using only Python's standard library "
    "(urllib.request, concurrent.futures, json, argparse, dataclasses, ssl). This means anyone can run the script "
    "on any machine having Python 3 installed without needing to pip install packages or set up virtual environments.",
    style='List Bullet'
)
doc.add_paragraph(
    "2. Active CORS Probing: Instead of just checking if CORS headers exist on a standard request, the scanner actively "
    "sends synthetic probes with different Origin values (such as an attacker domain, 'null', and regex prefix/suffix variations) "
    "to see how the server behaves when probed with unexpected origins.",
    style='List Bullet'
)
doc.add_paragraph(
    "3. Actionable Security Scoring: Instead of giving developers a raw dump of headers, the tool calculates an easy-to-understand "
    "score (0–100) and gives concrete remediation snippets (like exact Nginx or Flask code) for every issue found.",
    style='List Bullet'
)

# ================= 3. TECHNICAL METHODOLOGY =================
add_heading_1("3. Technical Methodology & How It Works")

add_heading_2("Part 1: HTTP Security Headers Auditor")
doc.add_paragraph(
    "The scanner inspects the target's HTTP response headers against OWASP guidelines. Below are the key headers checked:"
)
doc.add_paragraph("• Content-Security-Policy (CSP): Checks if CSP is present, warns if 'unsafe-inline' or 'unsafe-eval' are used, and verifies object-src restrictions.", style='List Bullet')
doc.add_paragraph("• Strict-Transport-Security (HSTS): Checks if HTTPS is enforced, whether max-age is at least 180 days (15552000s), and if includeSubDomains is enabled.", style='List Bullet')
doc.add_paragraph("• X-Frame-Options (XFO): Checks for 'DENY' or 'SAMEORIGIN' to prevent clickjacking in legacy browsers if CSP frame-ancestors is absent.", style='List Bullet')
doc.add_paragraph("• X-Content-Type-Options: Ensures 'nosniff' is set to prevent browsers from MIME-sniffing file uploads into executable scripts.", style='List Bullet')
doc.add_paragraph("• Referrer-Policy: Checks if referrer data is restricted (e.g. strict-origin-when-cross-origin) or if it dangerously leaks full paths (unsafe-url).", style='List Bullet')
doc.add_paragraph("• Permissions-Policy: Checks if sensitive browser features (camera, microphone, geolocation) are restricted.", style='List Bullet')
doc.add_paragraph("• Information Disclosure: Flags server banners like 'Server: Apache/2.4.41' or 'X-Powered-By: PHP/7.4.3' that give attackers version numbers for exploit targeting.", style='List Bullet')

add_heading_2("Part 2: CORS Vulnerability Probing")
doc.add_paragraph(
    "CORS misconfigurations are tested by sending realistic requests with specific Origin headers to the target endpoint:"
)
doc.add_paragraph(
    "1. Arbitrary Origin Reflection: The scanner sends 'Origin: https://attacker-security-test.com'. If the server reflects this origin back in Access-Control-Allow-Origin, it flags a misconfiguration.",
    style='List Bullet'
)
doc.add_paragraph(
    "2. Reflected Origin with Credentials (CRITICAL): If the server reflects the attacker's origin AND sets 'Access-Control-Allow-Credentials: true', this is marked CRITICAL. An attacker site can make authenticated cross-origin API calls using the victim's cookies and read the response.",
    style='List Bullet'
)
doc.add_paragraph(
    "3. Null Origin Trust (HIGH): The scanner sends 'Origin: null'. If accepted, attackers can bypass origin checks using sandboxed iframes (<iframe sandbox='allow-scripts'>) or data: URIs.",
    style='List Bullet'
)
doc.add_paragraph(
    "4. Subdomain & Prefix Regex Bypasses: Tests if weak origin regex matching allows origins like 'https://target.com.attacker.com' or 'https://attacker-target.com'.",
    style='List Bullet'
)

add_heading_2("Part 3: Scoring & Grade Calculation")
doc.add_paragraph(
    "Every audited site starts with 100 points. Penalties are deducted based on risk severity: "
    "-25 pts for missing CSP, -20 pts for missing HSTS, -30 pts for critical CORS credential reflection, "
    "-20 pts for null origin trust, -15 pts for missing X-Frame-Options, -10 pts for missing X-Content-Type-Options, "
    "and -5 pts for leaky server banners. Final scores map to standard grades: A+ (95–100), A (85–94), B (75–84), C (60–74), D (45–59), F (<45)."
)

# ================= 4. CODE IMPLEMENTATION =================
add_heading_1("4. Code Implementation Highlights")
doc.add_paragraph(
    "The code is structured into clean, modular classes inside scanner.py:"
)
doc.add_paragraph("• HeaderAuditor: Contains rule-checking logic and explanations for each HTTP security header.", style='List Bullet')
doc.add_paragraph("• CORSAuditor: Executes probes for synthetic origin headers and tests the server's access control response.", style='List Bullet')
doc.add_paragraph("• WebScanner: Coordinates target scanning, handles multi-threading (ThreadPoolExecutor) for scanning URL lists, and calculates final scores.", style='List Bullet')
doc.add_paragraph("• Reporter: Formats scan findings into colored terminal tables, structured JSON, or clean standalone HTML.", style='List Bullet')

add_callout(
    "I also built a `--demo` flag directly into the script. This allows anyone (such as a bootcamp evaluator or teammate) "
    "to run the script offline without an internet connection and see a side-by-side comparison of a vulnerable target vs. a secure target.",
    title="PRACTICAL FEATURE"
)

# ================= 5. TESTING & RESULTS =================
add_heading_1("5. Testing & Experimental Results")
doc.add_paragraph(
    "I thoroughly tested the script in two ways: first by creating an automated unit test suite (tests/test_scanner.py) "
    "to test individual header rules, and second by running the scanner against test endpoints."
)

add_heading_2("Unit Test Results")
doc.add_paragraph(
    "Running `python3 -m unittest discover -s tests -p 'test_*.py' -v` passes 5/5 tests in under 0.01 seconds:"
)
doc.add_paragraph("✓ test_missing_all_security_headers: Confirms that a site with no headers gets flagged and drops below 50 points.", style='List Bullet')
doc.add_paragraph("✓ test_strong_security_headers: Confirms that properly configured headers score an A+ (95+).", style='List Bullet')
doc.add_paragraph("✓ test_weak_csp_warning: Confirms that CSP with unsafe-inline generates a warning.", style='List Bullet')
doc.add_paragraph("✓ test_information_leakage_detection: Confirms that Server/PHP banners are detected.", style='List Bullet')
doc.add_paragraph("✓ test_grade_calculation: Confirms score-to-grade mapping logic.", style='List Bullet')

add_heading_2("Sample Terminal Output")
doc.add_paragraph("Below is the terminal output generated when auditing a vulnerable test endpoint:")

# Terminal snippet
tbl_code = doc.add_table(rows=1, cols=1)
tbl_code.alignment = WD_TABLE_ALIGNMENT.CENTER
c_code = tbl_code.cell(0, 0)
c_code.width = Inches(6.5)
shd_code = f'<w:shd {nsdecls("w")} w:fill="22272E"/>'
c_code._tc.get_or_add_tcPr().append(parse_xml(shd_code))
p_c = c_code.paragraphs[0]
p_c.paragraph_format.space_before = Pt(4)
p_c.paragraph_format.space_after = Pt(4)
r_raw = p_c.add_run(
    "----------------------------------------------------------------------\n"
    "[1/1] Target: https://vulnerable-portal.local/api\n"
    "Scan Time: 2026-10-24 15:46:57 | HTTP Status: 200 | Latency: 142.5 ms\n"
    "Security Score: 35/100 (Grade: F)\n"
    "----------------------------------------------------------------------\n"
    "--- [1] HTTP SECURE HEADERS AUDIT ---\n"
    "  [FAIL] Content-Security-Policy (Severity: HIGH)\n"
    "         Missing CSP header. The application is vulnerable to XSS and Clickjacking.\n"
    "  [FAIL] Strict-Transport-Security (Severity: HIGH)\n"
    "         Missing HSTS header on HTTPS connection. Vulnerable to SSL-stripping.\n"
    "  [FAIL] X-Frame-Options (Severity: MEDIUM)\n"
    "         Missing X-Frame-Options. Page can be framed for Clickjacking attacks.\n"
    "  [PASS] X-Content-Type-Options (Severity: PASS)\n"
    "         MIME-sniffing protection is properly enabled ('nosniff').\n"
    "--- [2] CORS MISCONFIGURATION PROBING ---\n"
    "  [CRITICAL] Arbitrary Origin Reflection with Credentials\n"
    "         Test Origin: https://attacker-security-test.com\n"
    "         Finding: Server reflects arbitrary Origin AND sets Access-Control-Allow-Credentials: true.\n"
    "         ACAO Header: https://attacker-security-test.com | ACAC Header: true\n"
    "  [HIGH] Null Origin Trust\n"
    "         Test Origin: null | Finding: Server explicitly trusts 'null' origin."
)
r_raw.font.name = 'Consolas'
r_raw.font.size = Pt(8.5)
r_raw.font.color.rgb = RGBColor(230, 237, 243)
doc.add_paragraph()

# ================= 6. CHALLENGES & SOLUTIONS =================
add_heading_1("6. Challenges Faced & How I Solved Them")
doc.add_paragraph(
    "During development and testing, I ran into a few real-world hurdles:"
)
doc.add_paragraph(
    "1. Handling SSL Certificates on Local/Staging Servers: When testing development endpoints or internal self-signed servers, "
    "Python's urllib throws an SSLCertVerificationError. To solve this, I added a `-k / --insecure` flag that creates an unverified "
    "SSL context when specifically requested, making testing on lab environments seamless.",
    style='List Bullet'
)
doc.add_paragraph(
    "2. User-Agent Blocking: Several web servers block requests with Python's default User-Agent ('Python-urllib/3.13'). "
    "I resolved this by setting a standard browser User-Agent header in the request object so scans don't get falsely blocked.",
    style='List Bullet'
)
doc.add_paragraph(
    "3. Accurate CORS Interpretation: In CORS, a wildcard '*' without credentials is fine for public open data (like public weather APIs), "
    "but dangerous if credentials are enabled. I made sure my logic specifically looks for the combination of reflection or wildcards "
    "with `Access-Control-Allow-Credentials: true` to avoid false alarms on purely public APIs.",
    style='List Bullet'
)

# ================= 7. REMEDIATION & HARDENING =================
add_heading_1("7. Defensive Remediation Guide")
doc.add_paragraph(
    "For any site flagged by the scanner, fixing the findings is straightforward. Below are the recommended fixes:"
)

add_heading_2("Nginx Configuration Fix")
doc.add_paragraph(
    "In your Nginx site configuration (/etc/nginx/sites-available/default), add these lines inside the server block:"
)
p_ng = doc.add_paragraph()
r_ng = p_ng.add_run(
    "# Add security headers\n"
    "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;\n"
    "add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none';\" always;\n"
    "add_header X-Frame-Options \"DENY\" always;\n"
    "add_header X-Content-Type-Options \"nosniff\" always;\n"
    "add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;\n"
    "server_tokens off;"
)
r_ng.font.name = 'Consolas'
r_ng.font.size = Pt(8.5)
r_ng.font.color.rgb = COLOR_DARK

add_heading_2("CORS Backend Fix (Python / Flask)")
doc.add_paragraph(
    "Instead of echoing the incoming Origin header, maintain a strict whitelist of trusted frontend domains:"
)
p_py = doc.add_paragraph()
r_py = p_py.add_run(
    "# Secure Whitelisted CORS in Python\n"
    "ALLOWED_ORIGINS = {'https://myapp.com', 'https://admin.myapp.com'}\n\n"
    "@app.after_request\n"
    "def set_cors(response):\n"
    "    origin = request.headers.get('Origin')\n"
    "    if origin in ALLOWED_ORIGINS:\n"
    "        response.headers['Access-Control-Allow-Origin'] = origin\n"
    "        response.headers['Access-Control-Allow-Credentials'] = 'true'\n"
    "        response.headers['Vary'] = 'Origin'\n"
    "    return response"
)
r_py.font.name = 'Consolas'
r_py.font.size = Pt(8.5)
r_py.font.color.rgb = COLOR_DARK

# ================= 8. CONCLUSION & LEARNINGS =================
add_heading_1("8. Key Learnings & Conclusion")
doc.add_paragraph(
    "Working on this project for the IBM SkillsBuild Bootcamp gave me direct hands-on experience with how browser security "
    "controls really work behind the scenes. It showed me that securing a web application isn't just about sanitizing SQL queries—it "
    "also requires configuring the HTTP transport layer and cross-origin access controls properly."
)
doc.add_paragraph(
    "By writing this automated Python scanner from scratch, I developed a deeper understanding of OWASP A05 (Security Misconfiguration), "
    "how preflight OPTIONS requests work, and why blind origin reflection is so dangerous. The tool is fast, lightweight, and ready to be "
    "integrated into CI/CD pipelines or used as a standalone security auditing tool."
)

doc.add_paragraph("References:", style='Normal')
doc.add_paragraph("1. OWASP Top 10 (A05:2021 - Security Misconfiguration)", style='List Bullet')
doc.add_paragraph("2. OWASP Secure Headers Project Guide", style='List Bullet')
doc.add_paragraph("3. MDN Web Docs: Cross-Origin Resource Sharing (CORS) & Content Security Policy (CSP)", style='List Bullet')
doc.add_paragraph("4. IBM SkillsBuild National Cybersecurity Bootcamp Sessions, BharatCares & IBM (October 2026)", style='List Bullet')

docx_file_path = os.path.join(output_dir, "Project_Report_Automated_Web_Scanner.docx")
doc.save(docx_file_path)
print(f"[+] Successfully created humanized Word (.docx) report at: {docx_file_path}")
