#LetsDefend Challenge Report: MSHTML Maldoc Analysis#

Author: Stanley Sajere
Challenge Title: MSHTML – Maldoc Analysis
Platform: LetsDefend
Tools Used: zipdump.py, re-search.py, numbers-to-string.py, VirusTotal
Focus: Identifying embedded indicators and exploited CVEs within malicious Microsoft Office documents

🔍 Objective

Analyse a set of suspicious Office documents to:

    Extract Indicators of Compromise (IP addresses and domains)

    Identify the vulnerability being exploited

    Practice real-world malware document analysis using blue team techniques and forensic tools

🧰 Tools & Techniques

    zipdump.py – Unpacks OOXML/ZIP structures in Office files

    re-search.py – Scans output for patterns like IPs, domains using regex

    numbers-to-string.py – Converts embedded numerical data back to readable strings

    VirusTotal – Cross-verification of hashes, domains, and IPs for threat intel
