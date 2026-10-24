#!/usr/bin/env python3
"""
Compiles all project documentation and code into clean, print-ready PDFs.
Outputs:
1. Project_Report_Automated_Web_Scanner.pdf (Already generated, 8 pages)
2. README_Automated_Web_Scanner.pdf (Formatted README as PDF)
3. Code_File_Scanner.pdf (Syntax highlighted code printout)
4. Project_Submission_Guide.pdf (Cheat-sheet summary for form submission)
"""

import os
import subprocess
import shutil

project_dir = "/Users/away/.gemini/antigravity/scratch/IBM_Cybersecurity_Bootcamp_Project"
downloads_dir = "/Users/away/Downloads/IBM_Cybersecurity_Project_PDFs"
os.makedirs(downloads_dir, exist_ok=True)

# 1. Generate README PDF
readme_html_path = os.path.join(project_dir, "readme_pdf.html")
readme_pdf_path = os.path.join(project_dir, "README_Automated_Web_Scanner.pdf")

with open(os.path.join(project_dir, "README.md"), "r", encoding="utf-8") as f:
    readme_md = f.read()

# Simple HTML conversion for README
import html
escaped_md = html.escape(readme_md)

readme_html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>README - Automated Web Security Scanner</title>
<style>
    @page {{ size: A4; margin: 20mm; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; color: #1e293b; line-height: 1.6; font-size: 10pt; }}
    pre {{ background: #f8fafc; border: 1px solid #e2e8f0; padding: 12px; border-radius: 6px; font-family: monospace; font-size: 8.5pt; white-space: pre-wrap; }}
    h1 {{ color: #0f62fe; border-bottom: 2px solid #0f62fe; padding-bottom: 6px; }}
    h2 {{ color: #002d9c; margin-top: 20px; }}
    table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
    th, td {{ border: 1px solid #cbd5e1; padding: 8px 10px; text-align: left; font-size: 9pt; }}
    th {{ background: #edf5ff; color: #002d9c; }}
</style>
</head>
<body>
    <h1>README: Automated Web Security Scanner</h1>
    <p><strong>Topic 2:</strong> Programmed a Python script to audit sites for secure headers and CORS flaws.</p>
    <p><strong>Participant:</strong> Tarun Singh (GitHub: <a href="https://github.com/tarun-singh9897/automated-web-scanner">tarun-singh9897/automated-web-scanner</a>)</p>
    <p><strong>Program:</strong> IBM SkillsBuild National Cybersecurity Bootcamp</p>
    <hr>
    <pre>{escaped_md}</pre>
</body>
</html>"""

with open(readme_html_path, "w", encoding="utf-8") as f:
    f.write(readme_html)

subprocess.run([
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "--headless=new",
    "--disable-gpu",
    f"--print-to-pdf={readme_pdf_path}",
    readme_html_path
], check=True)
print(f"[+] Compiled {readme_pdf_path}")

# 2. Generate Code File PDF
code_html_path = os.path.join(project_dir, "code_pdf.html")
code_pdf_path = os.path.join(project_dir, "Code_File_Scanner.pdf")

with open(os.path.join(project_dir, "scanner.py"), "r", encoding="utf-8") as f:
    code_content = f.read()

code_html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Source Code: scanner.py - Automated Web Scanner</title>
<style>
    @page {{ size: A4; margin: 15mm; }}
    body {{ font-family: Consolas, "Liberation Mono", Menlo, monospace; color: #1e1e1e; line-height: 1.4; font-size: 8pt; }}
    .header {{ font-family: -apple-system, sans-serif; border-bottom: 2px solid #0f62fe; padding-bottom: 10px; margin-bottom: 15px; }}
    .header h1 {{ margin: 0 0 5px 0; font-size: 16pt; color: #0f62fe; }}
    .header p {{ margin: 0; font-size: 9pt; color: #475569; }}
    pre {{ white-space: pre-wrap; word-break: break-all; margin: 0; }}
</style>
</head>
<body>
    <div class="header">
        <h1>Source Code: scanner.py</h1>
        <p><strong>Project:</strong> Automated Web Scanner (Secure Headers & CORS Flaws Audit)</p>
        <p><strong>Author:</strong> Tarun Singh | GitHub: tarun-singh9897/automated-web-scanner</p>
        <p><strong>Event:</strong> IBM SkillsBuild National Cybersecurity Bootcamp</p>
    </div>
    <pre>{html.escape(code_content)}</pre>
</body>
</html>"""

with open(code_html_path, "w", encoding="utf-8") as f:
    f.write(code_html)

subprocess.run([
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "--headless=new",
    "--disable-gpu",
    f"--print-to-pdf={code_pdf_path}",
    code_html_path
], check=True)
print(f"[+] Compiled {code_pdf_path}")

# 3. Generate Submission Quick Reference Guide PDF
guide_html_path = os.path.join(project_dir, "guide_pdf.html")
guide_pdf_path = os.path.join(project_dir, "Submission_Quick_Reference_Guide.pdf")

guide_html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>IBM SkillsBuild Cybersecurity Bootcamp - Submission Reference Guide</title>
<style>
    @page {{ size: A4; margin: 20mm; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; color: #1e293b; line-height: 1.6; font-size: 10.5pt; }}
    .card {{ border: 1px solid #cbd5e1; border-radius: 8px; padding: 18px; margin-bottom: 15px; background: #ffffff; }}
    h1 {{ color: #0f62fe; margin-top: 0; }}
    h2 {{ color: #002d9c; font-size: 14pt; margin-top: 0; }}
    .badge {{ display: inline-block; background: #edf5ff; color: #002d9c; padding: 4px 10px; border-radius: 12px; font-weight: bold; font-size: 9pt; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}
    th, td {{ border: 1px solid #cbd5e1; padding: 10px; text-align: left; font-size: 9.5pt; }}
    th {{ background: #0f62fe; color: white; }}
    code {{ background: #f1f5f9; padding: 2px 5px; border-radius: 4px; font-size: 9pt; color: #002d9c; }}
</style>
</head>
<body>
    <h1>IBM SkillsBuild Cybersecurity Bootcamp - Capstone Submission</h1>
    <p><strong>Project Topic:</strong> 2. Automated Web Scanner: Programmed a Python script to audit sites for secure headers and CORS flaws.</p>
    <p><strong>Participant:</strong> Tarun Singh | <strong>GitHub:</strong> <a href="https://github.com/tarun-singh9897/automated-web-scanner">https://github.com/tarun-singh9897/automated-web-scanner</a></p>
    <p><strong>Live Repository:</strong> <code>https://github.com/tarun-singh9897/automated-web-scanner</code></p>
    <hr>
    <h2>Google Form Field-to-File Mapping</h2>
    <table>
        <thead>
            <tr>
                <th>Form Field</th>
                <th>File to Upload / Value</th>
                <th>File Description</th>
            </tr>
        </thead>
        <tbody>
            <tr>
                <td><strong>1. Code File *</strong></td>
                <td><code>scanner.py</code><br><em>(or <code>Code_File_Scanner.pdf</code>)</em></td>
                <td>Zero-dependency Python 3 security scanner with headers audit, active CORS probes, and reporting.</td>
            </tr>
            <tr>
                <td><strong>2. Requirements File *</strong></td>
                <td><code>requirements.txt</code></td>
                <td>Requirements specification documenting standard library execution and development tools.</td>
            </tr>
            <tr>
                <td><strong>3. Project Report *</strong></td>
                <td><code>Project_Report_Automated_Web_Scanner.pdf</code></td>
                <td>Formal 8-page Capstone Project Report covering background, architecture, test results, and hardening guides.</td>
            </tr>
            <tr>
                <td><strong>4. README File *</strong></td>
                <td><code>README.md</code><br><em>(or <code>README_Automated_Web_Scanner.pdf</code>)</em></td>
                <td>Comprehensive documentation, CLI flags, security score table, and usage examples.</td>
            </tr>
            <tr>
                <td><strong>5. GitHub Repository *</strong></td>
                <td><code>https://github.com/tarun-singh9897/automated-web-scanner</code></td>
                <td>Public GitHub repository with all code, tests, and documentation.</td>
            </tr>
        </tbody>
    </table>
</body>
</html>"""

with open(guide_html_path, "w", encoding="utf-8") as f:
    f.write(guide_html)

subprocess.run([
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "--headless=new",
    "--disable-gpu",
    f"--print-to-pdf={guide_pdf_path}",
    guide_html_path
], check=True)
print(f"[+] Compiled {guide_pdf_path}")

# Copy all PDFs to Downloads folder
all_pdfs = [
    "Project_Report_Automated_Web_Scanner.pdf",
    "README_Automated_Web_Scanner.pdf",
    "Code_File_Scanner.pdf",
    "Submission_Quick_Reference_Guide.pdf"
]

for pdf in all_pdfs:
    src = os.path.join(project_dir, pdf)
    dst = os.path.join(downloads_dir, pdf)
    if os.path.exists(src):
        shutil.copy2(src, dst)
        print(f"[+] Copied {pdf} to {downloads_dir}")

print("[✓] All PDFs successfully generated and copied to Downloads!")
