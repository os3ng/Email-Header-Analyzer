# 🛡️ Email Header Analyzer — Spoofing & Brand Lookalike Detection

Python + Streamlit cybersecurity portfolio project for **defensive email triage**.
It examines .eml headers, reports suspicious signs, and explains a heuristic risk score.
It does **not** prove whether an email is malicious or independently verify authentication.

## Features

- Displays **reported** SPF, DKIM, DMARC results from the first `Authentication-Results` header.
- Flags `From` versus `Reply-To` domain mismatch.
- Flags **brand impersonation** (Maybank demo) using a configurable `brand_domains.json` reference list.
- Detects likely **typosquatting** (edit distance 1–2), **brand + extra terms**, **fake subdomains** (e.g., `maybank2u.com.my.fake.example`), **limited Unicode lookalikes**, and **display-name impersonation**.
- Includes synthetic sample messages and automated tests.
- Works locally; no network requests or API keys required.

## Demo

A message claiming `"Maybank Security" <alerts@maybannk2u.com.my>` with reported `dmarc=pass` still triggers a **domain-lookalike warning**. A sender can authenticate its own lookalike domain: DMARC pass alone never establishes that its claims about a brand are true.

## Quick start — Windows 11 (PowerShell)

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m streamlit run app.py
```

Open <http://localhost:8501> and upload `samples/maybank-lookalike.eml`.
Compare to `samples/normal.eml` and `samples/suspicious.eml`.

Run automated tests:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -v
```

## Brand reference list

Edit `brand_domains.json` to add your own **verified reference domains**. The included Maybank entries reflect official web/email reference domains, **not** an exhaustive or guaranteed allowlist of legitimate Maybank sending infrastructure. A website domain does not necessarily cover all legitimate email senders. Exact/subdomain matches are only skipped for the *lookalike* check — never called authenticated.

## Accuracy and threat model

- **Untrusted raw email headers:** `Authentication-Results`, `From`, `Return-Path`, and even a sender-visible display name can be forged. This tool parses reports; it does **not** validate DKIM cryptographically, rerun SPF from a trusted mail gateway, or apply a verified DMARC policy.
- **False positives:** legitimate third-party senders, marketing services or new domains might mention a brand. Edit-distance heuristics do not prove malicious intent.
- **False negatives:** sophisticated Unicode confusables, zero-width characters, long multi-label domains, compromised real sending accounts, or phishing from unrelated names may evade these checks.
- **Risk score:** hand-weighted triage aid; 100/100 does **not** mean a 100% chance of maliciousness.
- Do not use this as your sole security control and do not upload real, private messages into a public repository.

## Sources

- [Maybank: Phishing Scam FAQs](https://www.maybank2u.com.my/maybank2u/malaysia/en/personal/faq/online_banking/phishing_scam_faqs.page)
- [Maybank: Online Banking Safety Tips](https://www.maybank2u.com.my/maybank2u/malaysia/en/personal/security_alert/online_banking_safety_tips.page)
- [RFC 7489: Domain-based Message Authentication, Reporting, and Conformance](https://www.rfc-editor.org/rfc/rfc7489)

## Next improvements

- Parse `Authentication-Results` only from a **trusted** mail receiver, rather than the first arbitrary header.
- Validate domain alignment based on verified upstream authentication results.
- Add registrable-domain parsing using the Public Suffix List, richer Unicode confusable handling, and benchmarked precision/recall on labeled examples.
- Add an optional attachment/URL inspection module with appropriate sandboxing.


git push -u origin main
```

Replace `YOUR_USERNAME` with your GitHub username. You may need to sign in to GitHub through your Git credential manager.
