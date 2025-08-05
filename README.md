# 🛡️ ReconForge - World-Class Network & Web Reconnaissance Toolkit

**Version:** 19.0 – Consolidated & Complete Edition
**Author:** [Gemini](https://github.com/yourusername)
**License:** MIT

---

## 🌐 Overview

**ReconForge** is a professional-grade, modular, and extensible **network and web reconnaissance** Bash toolkit. Built for both **Capture The Flag (CTF)** challenges and **real-world penetration testing**, it combines industry-standard tools with intelligent logic and reporting.

ReconForge goes beyond a simple recon script — it's a full-fledged scanning framework that supports passive + active recon, intelligent subdomain fuzzing, robust error handling, rich HTML/Markdown reports, and precision-tuned directory brute-forcing.

---

## 🚀 Key Features

* 🔍 **Passive Reconnaissance**

  * WHOIS, DNS records, dig, nslookup
  * Full raw WHOIS output preservation
* ⚡ **Active Network Scanning**

  * Smart port detection using `rustscan`
  * Deep service enumeration using `nmap`
* 🌐 **Web Enumeration**

  * `WhatWeb`, `FFUF`, `robots.txt`, `sitemap.xml`, HTTP headers, etc.
  * Subdomain scanning with custom or default wordlists
  * Auto-filtering and directory brute-force calibration
* 📊 **Beautiful Reporting**

  * Markdown + HTML reports using `pandoc`
  * JSON + styled logs via `jq`
* 🔁 **Flexible Modes**

  * Silent Mode, Dry-Run Preview, Minimal Scan, Lite Mode
* 🛡️ **Error-Handled, Modular, and Clean**

  * Graceful exits on error/timeouts
  * Clear folder hierarchy for each scan

---

## 📁 Output Directory Structure

```
recon_results/
├── example.com-2025-08-05/
│   ├── passive/
│   ├── nmap/
│   ├── web/
│   ├── subdomains/
│   ├── screenshots/
│   ├── SUMMARY.md
│   ├── REPORT.html
│   └── scan.log
```

---

## 🛠️ Installation Instructions (From Scratch)

### ✅ Step 1: Clone the Repository

```bash
git clone https://github.com/yourusername/reconforge.git
cd reconforge
chmod +x recon.sh
```

### ✅ Step 2: Install Dependencies

ReconForge uses a wide range of tools. Install them using:

```bash
sudo apt update && sudo apt install -y \
  nmap rustscan ffuf whatweb jq curl whois \
  tree netcat telnet dig dnsutils pandoc \
  libxml2-utils gnupg lsof unzip
```

---

## ⚙️ Usage Instructions

### 📌 Basic Syntax

```bash
./recon.sh -d <domain_or_ip> [options]
```

### 🔧 Required Argument:

* `-d <target>`: Target IP or domain (e.g., `example.com` or `192.168.1.1`)

### 🔀 Modes & Options:

| Flag         | Description                               |
| ------------ | ----------------------------------------- |
| `-l`         | Lite Scan (skip web enum)                 |
| `-m`         | Minimal Scan (ports only)                 |
| `-s`         | Enable subdomain enumeration              |
| `--silent`   | Run silently with minimal terminal output |
| `--dry-run`  | Show commands without execution           |
| `-w <file>`  | Use custom wordlist for directory fuzzing |
| `-sw <file>` | Use custom wordlist for subdomain fuzzing |
| `--no-html`  | Skip HTML report generation               |

### 📥 Example Commands:

```bash
# Full Scan
./recon.sh -d example.com -s

# Scan with custom directory wordlist
./recon.sh -d example.com -w /usr/share/wordlists/dirbuster.txt

# Dry Run Preview
./recon.sh -d example.com --dry-run

# Minimal port scan only
./recon.sh -d 192.168.0.101 -m
```

---

## 📊 Reporting & Logs

* Markdown and HTML reports are saved in each scan directory.
* Logs include:

  * Raw tool outputs
  * JSON formatted summaries
  * Auto-generated `SUMMARY.md` + `REPORT.html`
* Easy to browse, share, and archive.

---

## 📦 Tool Integration Summary

| Tool           | Purpose                           |
| -------------- | --------------------------------- |
| `nmap`         | Deep port/service scan            |
| `rustscan`     | Fast port detection               |
| `ffuf`         | Directory & subdomain brute-force |
| `whatweb`      | Web tech fingerprinting           |
| `whois`        | Passive info gathering            |
| `jq`           | JSON processing and summaries     |
| `pandoc`       | Report conversion to HTML         |
| `dig/nslookup` | DNS enumeration                   |
| `curl`         | HTTP probing                      |

---

## 🧠 Example Workflow

1. Run a full recon scan:

```bash
./recon.sh -d target.com -s
```

2. Check results in:

```bash
recon_results/target.com-YYYY-MM-DD/
```

3. View the full summary:

```bash
cat SUMMARY.md
```

4. Share or open the HTML report:

```bash
xdg-open REPORT.html
```

---

## 🧪 Compatibility

Tested on:

* Kali Linux
* Parrot OS
* Ubuntu 20.04+

Supports both public targets and internal boxes.

---

## 📝 License

This project is licensed under the **MIT License** – see the [LICENSE](./LICENSE) file for details.

---

## ⚠️ Disclaimer

This script is for **educational and authorized security testing only**. Unauthorized use against systems without permission is strictly prohibited and may be illegal.

Use responsibly. Stay ethical.

---

## 📬 Contribute / Feedback

Got suggestions, bugs, or feature requests?

Open a GitHub Issue or Pull Request, or reach out via:

* GitHub: [yourusername](https://github.com/yourusername)
* Email: [your.email@domain.com](mailto:your.email@domain.com)

---

**Built with 💻 by Gemini | v19.0 - ReconForge | 2025**
