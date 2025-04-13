# LetsDefend Challenge Report: MSHTML Maldoc Analysis

![image](https://miro.medium.com/v2/resize:fit:720/format:webp/1*0o55Yebq_IS1I5klXv9fHg.png)

Author: Stanley Sajere <br>
Challenge Title: MSHTML – Maldoc Analysis<br>
Platform: LetsDefend<br>
Tools Used: zipdump.py, re-search.py, numbers-to-string.py, VirusTotal<br>
Focus: Identifying embedded indicators and exploited CVEs within malicious Microsoft Office documents<br>


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


📁 Sample Analysis
    
1️⃣ Employees_Contact_Audit_Oct_2021.docx

Goal: Extract malicious IP
Method:

    python3 zipdump.py -D sample.docx | python3 re-search.py -n -u ipv4

![image](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*DZwQL0ONBNH5DkOVg8HlFw.png)

![image](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*0Z2i2UxeMHgAX81rt5BfqA.png)

Result: Located a malicious IP embedded in the document
Follow-up: Confirmed threat via VirusTotal

2️⃣ Employee_W2_Form.docx

Goal: Identify suspicious domain
Method:

    python3 zipdump.py -D sample.docx | python3 re-search.py -n -u domaintld

![image](https://github.com/user-attachments/assets/55f83a83-3fa2-495e-81d3-444f673acc10)


Result: Extracted domain matched known threats in VirusTotal


3️⃣ Work_From_Home_Survey.doc

Goal: Decode embedded domain
Method:

    python3 zipdump.py -s 10 -d sample.doc | python3 numbers-to-string.py

![image](https://github.com/user-attachments/assets/56184db4-baa6-45bc-8d9c-0a964cf27479)


Result: Converted numerical data into a readable domain name


4️⃣ income_tax_and_benefit_return_2021.docx

Goal: Detect malicious URL
Method:

    python3 zipdump.py -D sample.docx | python3 re-search.py -n -u url-domain

![image](https://github.com/user-attachments/assets/4c058e2a-85e8-4776-aa79-ad2f5e7e6287)


Result: Confirmed malicious domain using VirusTotal correlation



⚠️ Final Discovery

Vulnerability Exploited:
CVE-2021-40444 – Remote Code Execution in MSHTML (ActiveX in Microsoft Office)

![image](https://github.com/user-attachments/assets/bd1f4e23-584b-4daf-8627-93ad9a63e105)


 A zero-day vulnerability allowing attackers to run arbitrary code via malicious Office documents.

🧠 Reflections

This challenge was a practical dive into malware document analysis. I became more confident using Didier Stevens’ tools and realised how effective inbuilt Python scripts can be for parsing structured document formats.

By layering tools (zipdump + re-search + VirusTotal), I could trace the IOCs and match them to a known CVE — a critical process for blue teamers.
📚 References

    SANS Cheat Sheet – Maldoc Analysis

    Didier Stevens Tools

    VirusTotal

    Microsoft Advisory – CVE-2021-40444
