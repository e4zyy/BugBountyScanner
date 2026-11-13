# BBScanner – Mass Web Vulnerability Scanner for Bug Bounty

A high‑coverage, multi‑phase bug bounty scanner that chains together best‑in‑class tools for subdomain enumeration, HTTP probing, port scanning, URL collection, vulnerability scanning, and specialized analysis.

Built by e4zyy | NOEL BUNSIAU.  
This project combines existing open‑source tools into a unified mass‑web vulnerability scanner for bug bounty workflows. We credit the original GitHub repos whose tools are used.

---

## Architecture Overview

The scanner operates in 6 phases for maximum coverage:
```bash
┌─────────────────────────────────────────────────────────────┐
│  PHASE 1: SUBDOMAIN ENUMERATION                             │
│  ├── Subfinder (passive + recursive)                        │
│  ├── Amass (OSINT aggregation)                              │
│  ├── Assetfinder (quick discovery)                          │
│  └── ShuffleDNS (bruteforce)                                │
├─────────────────────────────────────────────────────────────┤
│  PHASE 2: HTTP PROBING                                      │
│  └── Httpx (fast HTTP probing + tech detection)             │
├─────────────────────────────────────────────────────────────┤
│  PHASE 3: PORT SCANNING                                     │
│  └── Naabu (fast port scanning)                             │
├─────────────────────────────────────────────────────────────┤
│  PHASE 4: URL COLLECTION                                    │
│  ├── Waybackurls (archive.org)                              │
│  ├── Gau (alternative archive)                              │
│  └── Katana (active crawling)                               │
├─────────────────────────────────────────────────────────────┤
│  PHASE 5: VULNERABILITY SCANNING                            │
│  ├── Nuclei (main scanner - CVEs, exposures, misconfigs)    │
│  ├── Dalfox (XSS detection)                                 │
│  └── Custom exposure checks                                 │
├─────────────────────────────────────────────────────────────┤
│  PHASE 6: SPECIALIZED ANALYSIS                              │
│  ├── JavaScript analysis (secrets, endpoints)               │
│  ├── Parameter discovery (Arjun)                            │
│  └── Directory fuzzing (ffuf)                               │
└─────────────────────────────────────────────────────────────┘
```
---

## How to Launch

### Step 1: Install Dependencies

```bash
# Run the setup script
python3 bbscanner.py --setup
bash install_tools.sh

# Or manually install:
# Go tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/hahwul/dalfox/v2@latest

# Update nuclei templates
nuclei -update-templates

# Download wordlists
git clone https://github.com/danielmiessler/SecLists.git ~/wordlists
```

### Step 2: Prepare Target List

```bash
# Create targets.txt with domains to scan
cat > targets.txt << 'EOF'
example.com
target.com
bugbountyprogram.com
EOF
```

### Step 3: Launch the Scanner

```bash
# Basic scan
python3 bbscanner.py -l targets.txt

# Debug mode (verbose logging)
python3 bbscanner.py -l targets.txt --debug

# High-performance scan
python3 bbscanner.py -l targets.txt -t 100 -o results/

# With custom nuclei templates
python3 bbscanner.py -l targets.txt --nuclei-templates ~/custom-templates/
```

---

## Output Structure

```text
bb_results/
├── subdomains/          # Discovered subdomains
├── alive/               # Live HTTP hosts
├── nuclei/              # Vulnerability scan results
├── urls/                # Collected URLs (categorized)
├── ports/               # Port scan results
├── vulns/               # Specific vulnerability findings
├── tech/                # Technology detection
├── js/                  # JavaScript analysis
├── endpoints/           # Discovered endpoints
├── reports/             # Generated reports
│   ├── example.com_report_2026-08-09_10-30-00.md
│   └── MASTER_REPORT.md
└── scanner.log          # Debug log
```

The scanner will generate a `MASTER_REPORT.md` with all findings.

---

## Pro Tips for Maximum Payouts

1. **Start with Exposures** – Check `exposures/` and `misconfiguration/` templates first (quick wins).  
2. **Focus on APIs** – API endpoints often have IDOR and auth bypasses.  
3. **Check JavaScript** – Use the JS analysis for hardcoded keys and endpoints.  
4. **Re-scan After Fixes** – Programs pay for verified fixes.  
5. **Chain Vulnerabilities** – Combine low‑severity findings for higher impact.  
6. **Use Debug Mode** – `--debug` shows exactly what's being tested.  

---

## Credits

Coded by **e4zyy | NOEL BUNSIAU**.  
Some GitHub repos are credited because we use their repositories in this toolset. This scanner combines their tools into our mass‑web vulnerability scanner for bug bounty hunting.

Always use this tool responsibly and only against targets you are authorized to test.
