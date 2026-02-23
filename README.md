# Malicious Microsoft Office Document Analysis

This repository documents the static analysis of several malicious Microsoft Word documents (`.doc` and `.docx`).  
The analysis focuses on identifying **malicious IPs/domains** and the **vulnerabilities exploited**, **without executing the files**, demonstrating safe SOC / malware analysis practices.

---

## Analyzed Files & Findings

| File Name | Malicious Indicator | Type |
|-----------|------------------|------|
| Employees_Contact_Audit_Oct_2021.docx | 175.24.190.249 | IP Address |
| Employee_W2_Form.docx | arsenal.30cm.tw | Domain |
| Work_From_Home_Survey.doc | trendparlye.com | Domain |
| income_tax_and_benefit_return_2021.docx | hidusi.com | Domain |

---

## Vulnerability Exploited

**CVE-2021-40444** – Remote Code Execution via malicious ActiveX controls in Microsoft Word.  
- Exploited when a user opens a crafted document with external ActiveX content.  
- Common vector in phishing campaigns.

---

## Analysis Methodology

1. **Static Analysis Only** – safe investigation, no execution.  
2. **Tools & Techniques:**
   - `oledump.py` – Inspect OLE streams in `.doc` files
   - `olevba` – Extract VBA macros
   - `unzip` & `grep` – Inspect `.docx` XML relationships
   - `strings` – Search for embedded URLs/IPs  
3. **Steps:**
   - Identify file type (`file <filename>`)  
   - For `.docx`: unzip → search `_rels/document.xml.rels` for URLs/IPs  
   - For `.doc`: analyze OLE streams → locate hidden domains  
   - Document findings clearly  

---

## Key Takeaways

- Static analysis is **effective and safe** for malware investigation.  
- Malicious indicators may be **hidden in OLE streams or XML relationships**.  
- Knowledge of **CVE-2021-40444** and remote template injection is critical for SOC analysts.  

---

## References

- [oletools Documentation](https://www.decalage.info/python/oletools)  
- [CVE-2021-40444 Overview](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-40444)
